#!/usr/bin/env ruby
# frozen_string_literal: true

begin
  gem 'net-imap', '= 0.6.8'
  require 'net/imap'
rescue LoadError
  warn 'Install net-imap 0.6.8 in Ruby >= 3.2: gem install net-imap -v 0.6.8 --no-document'
  exit 2
end
require 'openssl'
require 'io/console'
require 'optparse'
require 'json'
require 'digest'
require 'fileutils'
require 'time'
require 'open3'
require 'timeout'
require 'tmpdir'
require 'tempfile'

module ReadMail
  class Error < StandardError; end
  CONNECTION_KEYS = %i[host user port allow_expired].freeze

  def self.platform
    return :windows if /mswin|mingw/ =~ RUBY_PLATFORM
    return :macos if RUBY_PLATFORM.include?('darwin')
    :other
  end

  def self.settings_directory
    case platform
    when :windows
      base = ENV['LOCALAPPDATA']
      raise Error, 'LOCALAPPDATA is unavailable; use your normal Windows user profile' if base.nil? || base.empty?
      File.join(base, 'ServerMailReadonly')
    when :macos then File.join(Dir.home, 'Library', 'Application Support', 'ServerMailReadonly')
    else File.join(ENV['XDG_CONFIG_HOME'] || File.join(Dir.home, '.config'), 'server-mail-readonly')
    end
  end

  def self.write_private(path, bytes)
    FileUtils.mkdir_p(File.dirname(path), mode: 0o700)
    # Close before rename: Windows cannot rename an open temporary file.
    temporary = nil
    Tempfile.create(['.write-', '.tmp'], File.dirname(path)) do |file|
      temporary = file.path
      file.binmode
      file.write(bytes)
      file.flush
      file.close
      File.rename(temporary, path)
    end
  ensure
    File.unlink(temporary) if temporary && File.exist?(temporary)
  end

  def self.load_config(path)
    return {} unless File.exist?(path)
    raw = JSON.parse(File.read(path, encoding: 'UTF-8'))
    allowed = %w[version host user port allow_expired]
    raise Error, 'Invalid config fields; the config must never contain a password' unless raw.is_a?(Hash) && (raw.keys - allowed).empty? && raw['version'] == 1
    connection = raw.reject { |key, _| key == 'version' }.transform_keys(&:to_sym)
    validate_connection(connection)
    connection
  rescue JSON::ParserError
    raise Error, 'Config is not valid UTF-8 JSON; recreate it with --configure'
  end

  def self.validate_connection(options)
    %i[host user].each do |key|
      value = options[key]
      raise Error, "Missing or invalid --#{key}; use --configure --host HOST --user LOGIN" unless value.is_a?(String) && !value.empty? && !value.match?(/[\x00-\x20\x7f]/)
    end
    raise Error, '--host must be a hostname or IP, without a URL scheme' if options[:host].include?('://')
    raise Error, 'Port must be 1..65535' unless options[:port].is_a?(Integer) && (1..65_535).cover?(options[:port])
    raise Error, 'allow_expired must be true or false' unless [true, false].include?(options[:allow_expired])
  end

  def self.identity(options)
    JSON.generate([options.fetch(:host).downcase, options.fetch(:port), options.fetch(:user)])
  end

  def self.keychain_service(options)
    "server-mail-readonly:#{options.fetch(:host).downcase}:#{options.fetch(:port)}"
  end

  def self.windows_secret_path(options)
    File.join(settings_directory, "password-#{Digest::SHA256.hexdigest(identity(options))}.dpapi")
  end

  # DPAPI uses the current Windows user, never CRYPTPROTECT_LOCAL_MACHINE.
  # Fiddle is included with RubyInstaller; no extra gem or PowerShell script is needed.
  def self.windows_api
    return @windows_api if @windows_api
    raise Error, 'DPAPI is available only on Windows' unless platform == :windows
    require 'fiddle/import'
    raise Error, 'Use 64-bit RubyInstaller on Windows' unless Fiddle::SIZEOF_VOIDP == 8
    system32 = File.join(ENV.fetch('SystemRoot', 'C:/Windows'), 'System32')
    api = Module.new
    api.extend(Fiddle::Importer)
    api.dlload(File.join(system32, 'crypt32.dll'), File.join(system32, 'kernel32.dll'))
    api.const_set(:Blob, api.struct(['unsigned int cbData', 'void* pbData']))
    api.extern('int CryptProtectData(void*, void*, void*, void*, void*, unsigned int, void*)')
    api.extern('int CryptUnprotectData(void*, void*, void*, void*, void*, unsigned int, void*)')
    api.extern('void* LocalFree(void*)')
    @windows_api = api
  end

  def self.dpapi(bytes, account_identity, decrypt: false)
    api = windows_api
    input = api::Blob.malloc(Fiddle::RUBY_FREE)
    entropy = api::Blob.malloc(Fiddle::RUBY_FREE)
    output = api::Blob.malloc(Fiddle::RUBY_FREE)
    raw = bytes.b
    binding = Digest::SHA256.digest(account_identity)
    input.cbData = raw.bytesize
    input.pbData = Fiddle::Pointer[raw]
    entropy.cbData = binding.bytesize
    entropy.pbData = Fiddle::Pointer[binding]
    output.cbData = 0
    output.pbData = 0
    function = decrypt ? :CryptUnprotectData : :CryptProtectData
    ok = api.public_send(function, input, 0, entropy, 0, 0, 1, output)
    raise Error, 'Windows DPAPI failed; use the same Windows user or save the password again' unless ok == 1
    output.pbData.to_s(output.cbData)
  ensure
    if output && !output.pbData.null?
      output.pbData[0, output.cbData] = "\0" * output.cbData if decrypt
      api.LocalFree(output.pbData)
    end
  end

  def self.saved_password(options)
    case platform
    when :macos
      value, _error, status = Open3.capture3('/usr/bin/security', 'find-generic-password',
                                           '-s', keychain_service(options), '-a', options.fetch(:user), '-w')
      return nil if status.exitstatus == 44
      raise Error, 'Keychain access denied or locked; ask the owner to unlock it' unless status.success?
      value.delete_suffix("\n")
    when :windows
      path = windows_secret_path(options)
      return nil unless File.exist?(path)
      dpapi(File.binread(path), identity(options), decrypt: true).force_encoding('UTF-8')
    end
  end

  def self.hidden_password
    raise Error, 'The owner must enter the password in an interactive terminal' unless $stdin.tty?
    $stderr.print 'IMAP password (hidden): '
    value = $stdin.noecho(&:gets)&.chomp
    $stderr.puts
    raise Error, 'Empty password' if value.nil? || value.empty?
    value
  end

  def self.save_password(options)
    raise Error, 'The owner must run --save-password in an interactive terminal' unless $stdin.tty?
    case platform
    when :macos
      # -w MUST be last: macOS prompts without putting the password in argv.
      ok = system('/usr/bin/security', 'add-generic-password', '-U',
                  '-s', keychain_service(options), '-a', options.fetch(:user),
                  '-l', 'Server mail read-only', '-w')
      raise Error, 'Could not save Keychain password' unless ok
    when :windows
      encrypted = dpapi(hidden_password.encode('UTF-8'), identity(options))
      write_private(windows_secret_path(options), encrypted)
    else
      raise Error, 'Persistent password storage supports macOS and Windows only; use hidden manual input on this OS'
    end
  end

  def self.tls_options(allow_expired: false)
    options = { verify_mode: OpenSSL::SSL::VERIFY_PEER, verify_hostname: true,
                min_version: OpenSSL::SSL::TLS1_2_VERSION }
    if allow_expired
      options[:verify_callback] = proc do |verified, context|
        verified || (context.error == OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED && context.error_depth.zero?)
      end
    end
    options
  end
  # EXAMINE is read-only; PEEK prevents implicitly setting the Seen flag.
  def self.export(imap, mailbox:, limit:, output:)
    imap.examine(mailbox)
    validity = imap.responses['UIDVALIDITY'].last
    raise 'Server did not return UIDVALIDITY' unless validity.is_a?(Integer) && validity.positive?

    uids = imap.uid_search(['ALL']).sort.last(limit)
    # A new directory per run avoids overwriting previous exports or following file symlinks.
    parent = File.expand_path(output)
    FileUtils.mkdir_p(parent, mode: 0o700)
    require 'tmpdir'
    directory = Dir.mktmpdir('imap-', parent)
    records = []
    uids.each do |uid|
      rows = imap.uid_fetch(uid, ['UID', 'FLAGS', 'INTERNALDATE', 'BODY.PEEK[]'])
      row = rows&.find { |item| item.attr['UID'] == uid }
      next unless row # Another client may have deleted the message meanwhile.

      raw = row.attr.fetch('BODY[]')
      filename = "#{uid}.eml"
      File.open(File.join(directory, filename), File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
        file.binmode
        file.write(raw)
      end
      records << { uid: uid, file: filename, sha256: Digest::SHA256.hexdigest(raw),
                   flags: row.attr['FLAGS'].map(&:to_s), internal_date: row.attr['INTERNALDATE'].to_s }
    end
    manifest = { exported_at: Time.now.utc.iso8601, mailbox: mailbox, uidvalidity: validity,
                 requested: uids.length, exported: records.length, messages: records }
    File.open(File.join(directory, 'manifest.json'), File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
      file.write(JSON.pretty_generate(manifest))
    end
    directory
  end

  def self.run(argv)
    imap = nil
    password = nil
    stage = 'setup'
    options = { mailbox: 'INBOX', limit: 100, output: File.join(__dir__, 'exports'), list: argv.empty? }
    overrides = {}
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby read_mail.rb --configure --host HOST --user LOGIN --save-password --list'
      opts.on('--config PATH', 'Settings JSON; defaults to your OS user profile') { |value| options[:config] = value }
      opts.on('--configure', 'Save server/login settings without saving the password in JSON') { options[:configure] = true }
      opts.on('--host HOST') { |value| overrides[:host] = value }
      opts.on('--user LOGIN') { |value| overrides[:user] = value }
      opts.on('--port PORT', Integer, 'Implicit TLS port; default 993') { |value| overrides[:port] = value }
      opts.on('--mailbox NAME') { |value| options[:mailbox] = value; options[:export] = true }
      opts.on('--limit N', Integer, 'Latest N UIDs; default 100') { |value| options[:limit] = value; options[:export] = true }
      opts.on('--output DIRECTORY') { |value| options[:output] = value; options[:export] = true }
      opts.on('--list', 'List folders only') { options[:list] = true }
      opts.on('--save-password', 'Owner saves a password in Keychain or Windows DPAPI') { options[:save_password] = true }
      opts.on('--allow-expired-certificate', 'Explicitly waive expiry of the leaf certificate only') { overrides[:allow_expired] = true }
      opts.on('--strict-certificate', 'Require a currently valid certificate (default)') { overrides[:allow_expired] = false }
      opts.on('--check', 'Check dependencies and config without credentials/network') { options[:check] = true }
      opts.on('-h', '--help') { puts opts; return 0 }
    end
    parser.parse!(argv)
    raise Error, 'Unexpected arguments; use --help' unless argv.empty?
    raise Error, '--limit must be positive' unless options[:limit].positive?
    config_path = File.expand_path(options[:config] || File.join(settings_directory, 'config.json'))
    connection = { port: 993, allow_expired: false }.merge(load_config(config_path)).merge(overrides)
    configured = connection[:host].is_a?(String) && connection[:user].is_a?(String)
    if options[:check]
      validate_connection(connection) if configured
      windows_api if platform == :windows
      puts JSON.pretty_generate(ruby: RUBY_VERSION, platform: RUBY_PLATFORM, net_imap: Net::IMAP::VERSION,
                                openssl: OpenSSL::OPENSSL_VERSION, configured: configured,
                                password_backend: { macos: 'Keychain', windows: 'DPAPI current user', other: 'manual input only' }.fetch(platform),
                                config: config_path, connection: connection, output: File.expand_path(options[:output]))
      return 0
    end
    validate_connection(connection)
    if options[:configure]
      write_private(config_path, JSON.pretty_generate({ version: 1 }.merge(connection)))
      puts "Settings saved: #{config_path}"
      return 0 unless options[:save_password] || options[:list] || options[:export]
    end
    stage = 'credentials'
    if options[:save_password]
      save_password(connection)
      password = saved_password(connection)
    else
      password = saved_password(connection) || hidden_password
    end
    raise Error, 'Saved password is empty; run --save-password again' if password.nil? || password.empty?
    Timeout.timeout(300) do
      stage = 'connect'
      imap = Net::IMAP.new(connection[:host], port: connection[:port], open_timeout: 20,
                           ssl: tls_options(allow_expired: connection[:allow_expired]), debug: false)
      stage = 'login'
      imap.login(connection[:user], password)
      if options[:list] || !options[:export]
        stage = 'list folders'
        puts JSON.pretty_generate((imap.list('', '*') || []).map { |folder| { name: folder.name, attributes: folder.attr } })
      else
        stage = 'export'
        directory = export(imap, mailbox: options[:mailbox], limit: options[:limit], output: options[:output])
        puts "Export saved: #{directory}"
      end
    end
    0
  rescue Error => error
    warn "IMAP #{stage}: #{error.message}"
    1
  rescue Net::IMAP::NoResponseError => error
    code = error.response.data.code&.name.to_s.gsub(/[^A-Za-z0-9_-]/, '')[0, 80]
    warn "IMAP #{stage} rejected (NO #{code}); check credentials, mailbox and server policy"
    1
  rescue StandardError => error
    warn "IMAP operation failed (#{error.class}) at #{stage}; check --help, config, TLS, credentials and output permissions"
    1
  ensure
    begin
      imap&.disconnect unless imap&.disconnected?
    rescue StandardError => error
      warn "IMAP disconnect failed (#{error.class})"
    end
  end
end

exit ReadMail.run(ARGV) if $PROGRAM_NAME == __FILE__

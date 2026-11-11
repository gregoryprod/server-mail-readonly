#!/usr/bin/env ruby
# frozen_string_literal: true

# Tested dependency profile; installation is explicit, never automatic.
begin
  gem 'net-imap', '= 0.6.8'
  require 'net/imap'
rescue LoadError => error
  warn 'Missing net-imap 0.6.8. Use Ruby >= 3.2 and run: gem install net-imap -v 0.6.8 --no-document'
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

module ReadMail
  def self.keychain_service(options)
    "materlux-imap:#{options.fetch(:host).downcase}:#{options.fetch(:port)}"
  end

  def self.keychain_password(options)
    return nil unless RUBY_PLATFORM.include?('darwin')

    value, _error, status = Open3.capture3('/usr/bin/security', 'find-generic-password',
                                        '-s', keychain_service(options), '-a', options.fetch(:user), '-w')
    return nil if status.exitstatus == 44 # errSecItemNotFound
    raise 'Keychain access failed' unless status.success?

    value.delete_suffix("\n")
  end

  def self.save_keychain_password(options)
    raise 'Keychain setup requires an interactive macOS terminal' unless RUBY_PLATFORM.include?('darwin') && $stdin.tty?

    # -w MUST be last: security prompts on the terminal, never putting the password in argv.
    saved = system('/usr/bin/security', 'add-generic-password', '-U',
                   '-s', keychain_service(options), '-a', options.fetch(:user),
                   '-l', 'Materlux IMAP', '-w')
    raise 'Could not save Keychain password' unless saved
  end

  def self.tls_options(allow_expired: false)
    options = { verify_mode: OpenSSL::SSL::VERIFY_PEER, verify_hostname: true,
                min_version: OpenSSL::SSL::TLS1_2_VERSION }
    if allow_expired
      # Only waive expiry of the leaf certificate, never trust or hostname errors.
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
    stage = 'setup'
    options = { host: 'mail.materlux.ru', user: 'order@materlux.ru', port: 993, allow_expired: true,
                mailbox: 'INBOX', limit: 100,
                output: File.join(__dir__, 'exports') }
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby read_mail.rb [options] (fixed account: order@materlux.ru)'
      opts.on('--mailbox NAME') { |value| options[:mailbox] = value }
      opts.on('--limit N', Integer, 'Latest N UIDs (default: 100)') { |value| options[:limit] = value }
      opts.on('--output DIRECTORY') { |value| options[:output] = value }
      opts.on('--list', 'List folders only') { options[:list] = true }
      opts.on('--save-password', 'Save password in macOS Keychain using a hidden native prompt') { options[:save_password] = true }
      opts.on('--strict-certificate', 'Require a currently valid certificate') { options[:allow_expired] = false }
      opts.on('--check', 'Check dependencies without accessing credentials or network') { options[:check] = true }
      opts.on('--allow-expired-certificate', 'Accept an expired leaf certificate; keep other TLS checks') { options[:allow_expired] = true }
      opts.on('-h', '--help') { puts opts; return 0 }
    end
    parser.parse!(argv)
    raise OptionParser::InvalidArgument, 'unexpected arguments' unless argv.empty?
    raise OptionParser::MissingArgument, '--host and --user' if [options[:host], options[:user]].any? { |v| v.nil? || v.empty? }
    raise OptionParser::InvalidArgument, '--limit must be positive' unless options[:limit].positive?
    raise OptionParser::InvalidArgument, '--port must be 1..65535' unless (1..65_535).cover?(options[:port])

    if options[:check]
      puts JSON.pretty_generate(ruby: RUBY_VERSION, platform: RUBY_PLATFORM, net_imap: Net::IMAP::VERSION,
                                openssl: OpenSSL::OPENSSL_VERSION, keychain_supported: RUBY_PLATFORM.include?('darwin'),
                                host: options[:host], user: options[:user], port: options[:port],
                                accept_expired_leaf: options[:allow_expired], output: File.expand_path(options[:output]))
      return 0
    end

    if options[:save_password]
      stage = 'keychain setup'
      save_keychain_password(options)
      password = keychain_password(options)
      raise 'Saved Keychain password is unavailable' if password.nil? || password.empty?
    else
      stage = 'credentials'
      password = ENV['IMAP_PASSWORD'] || keychain_password(options)
    end
    unless password
      raise 'Use an interactive terminal for password entry' unless $stdin.tty?
      $stderr.print 'IMAP password (hidden): '
      password = $stdin.noecho(&:gets)&.chomp
      $stderr.puts
    end
    raise 'Empty password' if password.nil? || password.empty?

    Timeout.timeout(300) do
      stage = 'connect'
      imap = Net::IMAP.new(options[:host], port: options[:port], open_timeout: 20,
                           ssl: tls_options(allow_expired: options[:allow_expired]), debug: false)
      stage = 'login'
      imap.login(options[:user], password)
      if options[:list]
        stage = 'list folders'
        puts JSON.pretty_generate((imap.list('', '*') || []).map { |folder| { name: folder.name, attributes: folder.attr } })
      else
        stage = 'export'
        directory = export(imap, mailbox: options[:mailbox], limit: options[:limit], output: options[:output])
        puts "Export saved: #{directory}"
      end
    end
    0
  rescue Net::IMAP::NoResponseError => error
    data = error.response.data
    reason = [data.code&.name, data.text].compact.join(': ')
    [password, options[:user]].compact.reject(&:empty?).uniq.sort_by { |value| -value.length }.each do |secret|
      reason = reason.gsub(secret, '[redacted]')
    end
    reason = reason.encode('UTF-8', invalid: :replace, undef: :replace).gsub(/[[:cntrl:]]/, ' ')[0, 300]
    warn "IMAP #{stage} rejected (NO): #{reason}"
    1
  rescue StandardError => error
    # Server error strings can contain login names and other private information.
    warn "IMAP operation failed (#{error.class}) at #{stage}. Check host, TLS, credentials, folder and output permissions."
    1
  ensure
    # Do not CLOSE: it can expunge messages marked Deleted in read-write sessions.
    begin
      imap&.disconnect unless imap&.disconnected?
    rescue StandardError => cleanup_error
      warn "IMAP disconnect failed (#{cleanup_error.class})."
    end
  end
end

# No arguments is a connectivity check, as in the original account launcher.
exit ReadMail.run(ARGV.empty? ? ['--list'] : ARGV) if $PROGRAM_NAME == __FILE__

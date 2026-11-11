# frozen_string_literal: true
require 'minitest/autorun'
require 'stringio'
require_relative '../read_mail'

class ReadMailTest < Minitest::Test
  class MailServer
    attr_reader :calls
    def initialize(empty: false)
      @calls = []
      @empty = empty
    end
    def login(*args) = @calls << [:login, *args]
    def list(*args)
      @calls << [:list, *args]
      [Struct.new(:name, :attr).new('INBOX', [:Haschildren])]
    end
    def examine(mailbox) = @calls << [:examine, mailbox]
    def responses = { 'UIDVALIDITY' => [123] }
    def uid_search(criteria)
      @calls << [:uid_search, criteria]
      @empty ? [] : [2, 5, 9]
    end
    def uid_fetch(uid, fields)
      @calls << [:uid_fetch, uid, fields]
      [Struct.new(:attr).new({ 'UID' => uid, 'FLAGS' => [], 'INTERNALDATE' => '2026-11-11',
                            'BODY[]' => "Subject: Synthetic fixture\r\n\r\nBinary \xff".b })]
    end
    def disconnected? = false
    def disconnect = @calls << [:disconnect]
  end

  def setup
    @directory = Dir.mktmpdir('mail setup space ')
    @config = File.join(@directory, 'settings.json')
    @account = { host: 'imap.example.test', user: 'reader@example.test', port: 993, allow_expired: false }
  end

  def teardown
    FileUtils.remove_entry(@directory)
  end

  def replaced(target, method, body)
    original = target.method(method)
    target.define_singleton_method(method, &body)
    yield
  ensure
    target.define_singleton_method(method, original)
  end

  def configure(*extra)
    stdout, stderr = capture_io do
      assert_equal 0, ReadMail.run(['--config', @config, '--configure', '--host', @account[:host], '--user', @account[:user], *extra])
    end
    assert_empty stderr
    assert_includes stdout, 'Settings saved:'
  end

  def test_configure_saves_only_connection_settings_and_check_is_offline
    replaced(ReadMail, :saved_password, ->(*) { raise 'must not read secrets' }) do
      replaced(Net::IMAP, :new, ->(*) { raise 'must not connect' }) do
        configure
        value = JSON.parse(File.read(@config))
        assert_equal %w[allow_expired host port user version], value.keys.sort
        assert_equal false, value['allow_expired']
        stdout, stderr = capture_io { assert_equal 0, ReadMail.run(['--config', @config, '--check']) }
        assert_empty stderr
        assert_equal true, JSON.parse(stdout)['configured']
      end
    end
  end

  def test_unconfigured_check_succeeds_but_read_fails_without_network
    stdout, stderr = capture_io { assert_equal 0, ReadMail.run(['--config', @config, '--check']) }
    assert_empty stderr
    assert_equal false, JSON.parse(stdout)['configured']
    replaced(Net::IMAP, :new, ->(*) { flunk('must not connect') }) do
      _stdout, stderr = capture_io { assert_equal 1, ReadMail.run(['--config', @config, '--list']) }
      assert_includes stderr, 'Missing or invalid --host'
    end
  end

  def test_malformed_config_and_password_field_are_rejected
    ['{bad', JSON.generate(version: 1, **@account, password: 'synthetic-never-echo')].each do |value|
      File.write(@config, value)
      stdout, stderr = capture_io { assert_equal 1, ReadMail.run(['--config', @config, '--list']) }
      assert_empty stdout
      refute_includes stderr, 'synthetic-never-echo'
    end
  end

  def test_invalid_limit_fails_before_reading_credentials
    replaced(ReadMail, :saved_password, ->(*) { flunk('must not read secrets') }) do
      _stdout, stderr = capture_io { assert_equal 1, ReadMail.run(['--limit', '0']) }
      assert_includes stderr, '--limit must be positive'
    end
  end

  def test_list_uses_saved_config_not_environment_and_preserves_all_tls_checks
    configure
    old_host, old_user = ENV['IMAP_HOST'], ENV['IMAP_USER']
    ENV['IMAP_HOST'], ENV['IMAP_USER'] = 'attacker.invalid', 'wrong'
    server = MailServer.new
    captured = nil
    replaced(ReadMail, :saved_password, ->(*) { 'synthetic-only' }) do
      replaced(Net::IMAP, :new, ->(host, **options) { captured = [host, options]; server }) do
        stdout, stderr = capture_io { assert_equal 0, ReadMail.run(['--config', @config, '--list']) }
        assert_empty stderr
        assert_equal 'INBOX', JSON.parse(stdout).first['name']
      end
    end
    assert_equal @account[:host], captured[0]
    assert_equal 993, captured[1][:port]
    assert_equal false, captured[1][:debug]
    tls = captured[1][:ssl]
    assert_equal OpenSSL::SSL::VERIFY_PEER, tls[:verify_mode]
    assert_equal true, tls[:verify_hostname]
    assert_equal OpenSSL::SSL::TLS1_2_VERSION, tls[:min_version]
    refute tls.key?(:verify_callback)
    assert_equal [[:login, @account[:user], 'synthetic-only'], [:list, '', '*'], [:disconnect]], server.calls
  ensure
    ENV['IMAP_HOST'], ENV['IMAP_USER'] = old_host, old_user
  end

  def test_expired_leaf_is_opt_in_and_other_failures_are_not_waived
    refute ReadMail.tls_options.key?(:verify_callback)
    callback = ReadMail.tls_options(allow_expired: true).fetch(:verify_callback)
    context = Struct.new(:error, :error_depth)
    assert callback.call(true, context.new(0, 0))
    assert callback.call(false, context.new(OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED, 0))
    refute callback.call(false, context.new(OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED, 1))
    [OpenSSL::X509::V_ERR_HOSTNAME_MISMATCH, OpenSSL::X509::V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
     OpenSSL::X509::V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY].each do |error|
      refute callback.call(false, context.new(error, 0))
    end
    configure('--allow-expired-certificate')
    assert_equal true, ReadMail.load_config(@config)[:allow_expired]
    configure('--strict-certificate')
    assert_equal false, ReadMail.load_config(@config)[:allow_expired]
  end

  def test_new_server_never_receives_saved_password_from_previous_server
    configure
    seen = nil
    replaced(ReadMail, :saved_password, ->(account) { seen = account; nil }) do
      replaced(ReadMail, :hidden_password, -> { raise ReadMail::Error, 'owner must enter a new password' }) do
        replaced(Net::IMAP, :new, ->(*) { flunk('must not send old password') }) do
          _stdout, stderr = capture_io { assert_equal 1, ReadMail.run(['--config', @config, '--host', 'second.example.test', '--list']) }
          assert_includes stderr, 'owner must enter a new password'
        end
      end
    end
    assert_equal 'second.example.test', seen[:host]
    refute_equal ReadMail.identity(@account), ReadMail.identity(seen)
    refute_equal ReadMail.keychain_service(@account), ReadMail.keychain_service(seen)
  end

  def test_export_peek_original_bytes_manifest_and_repeat_safety
    configure
    server = MailServer.new
    directories = []
    replaced(ReadMail, :saved_password, ->(*) { 'synthetic-only' }) do
      replaced(Net::IMAP, :new, ->(*) { server }) do
        2.times do
          result = nil
          stdout, stderr = capture_io do
            result = ReadMail.run(['--config', @config, '--limit', '1', '--output', @directory])
          end
          assert_equal 0, result, stderr
          assert_empty stderr
          directory = stdout.strip.delete_prefix('Export saved: ')
          directories << directory
          manifest = JSON.parse(File.read(File.join(directory, 'manifest.json')))
          assert_equal 123, manifest['uidvalidity']
          assert_equal 1, manifest['exported']
          item = manifest['messages'].first
          assert_equal 9, item['uid']
          raw = File.binread(File.join(directory, item['file']))
          assert_equal "Subject: Synthetic fixture\r\n\r\nBinary \xff".b, raw
          assert_equal Digest::SHA256.hexdigest(raw), item['sha256']
          unless ReadMail.platform == :windows
            assert_equal 0o600, File.stat(File.join(directory, item['file'])).mode & 0o777
          end
        end
      end
    end
    assert_equal 2, directories.uniq.length
    assert_equal 2, server.calls.count { |call| call.first == :disconnect }
    assert_equal [:examine, 'INBOX'], server.calls[1]
    assert server.calls.select { |call| call.first == :uid_fetch }.all? { |call| call.last.include?('BODY.PEEK[]') }
  end

  def test_empty_mailbox_has_completed_empty_manifest
    directory = ReadMail.export(MailServer.new(empty: true), mailbox: 'INBOX', limit: 1, output: @directory)
    manifest = JSON.parse(File.read(File.join(directory, 'manifest.json')))
    assert_equal 0, manifest['requested']
    assert_equal 0, manifest['exported']
    assert_empty manifest['messages']
  end

  def test_secret_backend_failure_stops_before_connection_without_details
    configure
    replaced(ReadMail, :saved_password, ->(*) { raise IOError, 'synthetic-private-detail' }) do
      replaced(Net::IMAP, :new, ->(*) { flunk('must not connect') }) do
        _stdout, stderr = capture_io { assert_equal 1, ReadMail.run(['--config', @config, '--list']) }
        assert_includes stderr, 'credentials'
        refute_includes stderr, 'synthetic-private-detail'
      end
    end
  end

  def test_keychain_identity_and_native_prompt_never_put_password_in_arguments
    old_stdin = $stdin
    $stdin = StringIO.new
    $stdin.define_singleton_method(:tty?) { true }
    calls = []
    replaced(ReadMail, :platform, -> { :macos }) do
      replaced(ReadMail, :system, ->(*args) { calls << args; true }) do
        ReadMail.save_password(@account)
      end
    end
    assert_equal ['-s', 'server-mail-readonly:imap.example.test:993', '-a', @account[:user]], calls.first[3, 4]
    assert_equal '-w', calls.first.last
    refute_includes calls.first, '-A'
  ensure
    $stdin = old_stdin
  end

  def test_atomic_settings_update_preserves_existing_file_on_prewrite_failure
    configure
    before = File.binread(@config)
    broken = Object.new
    broken.define_singleton_method(:to_s) { raise IOError, 'synthetic write failure' }
    assert_raises(IOError) { ReadMail.write_private(@config, broken) }
    assert_equal before, File.binread(@config)
    assert_empty Dir.glob(File.join(@directory, '.write-*'))
    configure('--port', '1993')
    assert_equal 1993, ReadMail.load_config(@config)[:port]
  end

  def test_windows_dpapi_roundtrip_and_binding_on_native_windows
    skip 'Native Windows DPAPI integration test' unless ReadMail.platform == :windows
    previous = ENV['LOCALAPPDATA']
    ENV['LOCALAPPDATA'] = @directory
    password = 'synthetic-only: Пароль £ ! & $ 123'
    encrypted = ReadMail.dpapi(password.encode('UTF-8'), ReadMail.identity(@account))
    refute_includes encrypted, password.b
    assert_equal password.b, ReadMail.dpapi(encrypted, ReadMail.identity(@account), decrypt: true)
    assert_raises(ReadMail::Error) { ReadMail.dpapi(encrypted, 'different-account', decrypt: true) }
    path = ReadMail.windows_secret_path(@account)
    2.times { ReadMail.write_private(path, encrypted) }
    assert_equal password, ReadMail.saved_password(@account)
    old_stdin = $stdin
    $stdin = StringIO.new
    $stdin.define_singleton_method(:tty?) { true }
    replaced(ReadMail, :hidden_password, -> { password }) { ReadMail.save_password(@account) }
    assert_equal password, ReadMail.saved_password(@account)
    second = @account.merge(host: 'second.example.test')
    refute_equal path, ReadMail.windows_secret_path(second)
    assert_nil ReadMail.saved_password(second)
    File.binwrite(path, 'corrupt-dpapi')
    assert_raises(ReadMail::Error) { ReadMail.saved_password(@account) }
  ensure
    $stdin = old_stdin if old_stdin
    ENV['LOCALAPPDATA'] = previous if ReadMail.platform == :windows
  end
end

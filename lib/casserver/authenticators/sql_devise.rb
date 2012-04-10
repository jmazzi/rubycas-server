require 'casserver/authenticators/sql'

# These were pulled directly from Devise, and new ones can be added
# just by including new Crypto Providers
require File.dirname(__FILE__) + '/authlogic_crypto_providers/aes256'
require File.dirname(__FILE__) + '/authlogic_crypto_providers/bcrypt'
require File.dirname(__FILE__) + '/authlogic_crypto_providers/md5'
require File.dirname(__FILE__) + '/authlogic_crypto_providers/sha1'
require File.dirname(__FILE__) + '/authlogic_crypto_providers/sha512'

begin
  require 'active_record'
rescue LoadError
  require 'rubygems'
  require 'active_record'
end

# This is a version of the SQL authenticator that works nicely with Devise.
# Passwords are encrypted the same way as it's done in Devise.
#
# Using this authenticator requires devise authentication plugin on rails (client) side.
#
# * git://github.com/plataformatec/devise.git
#
# Usage:

# authenticator:
#   class: CASServer::Authenticators::SQLDevise
#   database:
#     adapter: mysql
#     database: some_database_with_users_table
#     user: root
#     password:
#     server: localhost
#   user_table: user
#   username_column: email
#   password_column: encrypted_password
#   encryptor: BCrypt
#   encryptor_options:
#     stretches: 20
#
class CASServer::Authenticators::SQLDevise < CASServer::Authenticators::SQL

  def validate(credentials)
    read_standard_credentials(credentials)
    raise_if_not_configured

    user_model = self.class.user_model

    username_column = @options[:username_column] || "email"
    password_column = @options[:password_column] || "encrypted_password"
    salt_column     = @options[:salt_column]

    $LOG.debug "#{self.class}: [#{user_model}] " + "Connection pool size: #{user_model.connection_pool.instance_variable_get(:@checked_out).length}/#{user_model.connection_pool.instance_variable_get(:@connections).length}"
    results = user_model.find(:all, :conditions => ["#{username_column} = ?", @username])
    user_model.connection_pool.checkin(user_model.connection)

    begin
      encryptor = eval("Authlogic::CryptoProviders::" + (@options[:encryptor] || "BCrypt"))
    rescue
      $LOG.warn("Could not initialize Devise crypto class for '#{@options[:encryptor]}'")
      encryptor = Authlogic::CryptoProviders::BCrypt
    end

    if @options[:encryptor_options]
      @options[:encryptor_options].each do |name, value|
        encryptor.send("#{name}=", value) if encryptor.respond_to?("#{name}=")
      end
    end

    if results.size > 0
      $LOG.warn("Multiple matches found for user '#{@username}'") if results.size > 1
      user = results.first
      tokens = [@password, (not salt_column.nil?) && user.send(salt_column) || nil].compact
      crypted = user.send(password_column)

      unless @options[:extra_attributes].blank?
        if results.size > 1
          $LOG.warn("#{self.class}: Unable to extract extra_attributes because multiple matches were found for #{@username.inspect}")
        else
          extract_extra(user)
          log_extra
        end
      end

      return encryptor.matches?(crypted, tokens)
    else
      return false
    end
  end
end

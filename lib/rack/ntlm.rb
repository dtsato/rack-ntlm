require 'net/ntlm'
require 'net/ldap'

DOMAIN_CACHE = {}
NTLM_GET_HASH_REGEX = /^(NTLM|Negotiate) (.+)/

module Rack

  class Ntlm
    
    def initialize(app, config = {})
      @app = app
      @config = {}.merge(config)
    end

    def ad_auth(name, domain, is_user)
 
      ad = activedirectory_connect
      unless ad
        return -1 # ldap unavailable
      end

      search_params = { :name => name, :domain => domain }
      if is_user
        result = activedirectory_find_users(search_params)
      else
        result = activedirectory_find_computers(search_params)
      end     
      return result
    end # def ad_auth

    def call(env)
      if @config[:uri_pattern].blank?
        uri_matched = true
      else
        uri_matched = (env['PATH_INFO'] =~ @config[:uri_pattern])
      end

      if uri_matched
        if env['HTTP_AUTHORIZATION'].blank?
          return [401, {'WWW-Authenticate' => "NTLM"}, []]
        elsif NTLM_GET_HASH_REGEX =~ env['HTTP_AUTHORIZATION']
          ntlm_hash = $2
          message = Net::NTLM::Message.decode64(ntlm_hash)

          domain_key = "#{env['REMOTE_ADDR']},#{env['PATH_INFO']}"

          if message.type == 1
            DOMAIN_CACHE.delete(domain_key) if DOMAIN_CACHE[domain_key]

            type2 = Net::NTLM::Message::Type2.new
            type2.flag |= Net::NTLM::FLAGS[:NTLM]
            type2.flag |= Net::NTLM::FLAGS[:NTLM2_KEY]
            type2.flag |= Net::NTLM::FLAGS[:KEY128]
            type2.flag |= Net::NTLM::FLAGS[:KEY56]
            type2.challenge = rand((2**64) - 1)

            if message.workstation != message.domain
              DOMAIN_CACHE[domain_key] = message.domain
            end

            return [401, {"WWW-Authenticate" => "NTLM " + type2.encode64}, []]

          elsif message.type == 3 
            unless message.user.blank?
              user = message.user.to_s
              user = Net::NTLM::decode_utf16le(message.user)
              env['USERNAME'] = user 

              # For username logins, don't keep cache
              DOMAIN_CACHE.delete(domain_key) if DOMAIN_CACHE[domain_key]
            end

            unless message.workstation.blank?
              workstation = Net::NTLM::decode_utf16le(message.workstation)
              env['WORKSTATION'] = workstation
            end

            domain = nil
            unless message.domain.blank?
              domain = Net::NTLM::decode_utf16le(message.domain)
            end
            if domain.blank? && !DOMAIN_CACHE[domain_key].blank?
               domain = DOMAIN_CACHE[domain_key]
            end
            #domain = "WORKGROUP" if domain.blank?
            env['DOMAIN'] = domain

            if ENV['NO_AD'] && ENV['NO_AD'].to_i == 1
              env['AD_NOAUTH'] = "1"

            elsif user.blank? || user[-1].chr == '$'
              #############################################
              # Computer authentication
              #############################################

              workstation += '$' if workstation[-1].chr != '$'

              @results = ad_auth(workstation, domain, false)
              if @results == -1 # ldap unavailable
                env['AD_NOAUTH'] = "1"

              elsif @results
                env['AD_ENTRY'] = @results.first

              else
                env['AD_FAILEDAUTH'] = "1"
                #return [401, {}, ['You are not authorized to see this page']]
              end

            else 
              #############################################
              # User authentication
              #############################################

              @results = ad_auth(user, domain, true)
              if @results == -1 # ldap unavailable
                env['AD_NOAUTH'] = "1"

              elsif @results
                env['AD_ENTRY'] = @results.first

              else
                env['AD_FAILEDAUTH'] = "1"
                #return [401, {}, ['You are not authorized to see this page']]
              end

            end # ENV['NO_AD'] && ENV['NO_AD'].to_i == 1

          else 
            return [401, {}, ['Your browser does not support Integrated Windows Authentication']]
          end # message.type
        end # if NTLM_GET_HASH_REGEX =~ env['HTTP_AUTHORIZATION']
      end # uri_matched

      @app.call(env)
    end # def call(env)
  
  end # Class
end # Module

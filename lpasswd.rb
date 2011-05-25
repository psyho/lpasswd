#!/usr/bin/env ruby

require 'rubygems'
require 'net-ldap'
require 'sinatra'

require 'digest/sha1'
require 'base64'
require 'yaml'

class LDAP
  attr_accessor :host, :port, :base, :username_pattern, :admin, :admin_password

  attr_reader :connection

  def initialize(opts = {})
    opts.each{ |key, val| send("#{key}=", val) }

    @connection = Net::LDAP.new :host => host, :base => base, :port => port
  end

  def login_as(user_id, password)
    connection.authenticate(user_id, password)
    return connection.bind
  end

  def login_as!(user_id, password)
    raise "Invalid login!" unless login_as(user_id, password)
  end

  def valid_login?(username, password)
    return login_as(user_id_from_name(username), password)
  end

  def change_password(username, password)
    login_as!(admin, admin_password)

    user_id = user_id_from_name(username)
    encoded_password = Net::LDAP::Password.generate(:sha, password)
    operations = [[:replace, :userPassword, encoded_password]]

    return connection.modify(:dn => user_id, :operations => operations)
  end

  def user_id_from_name(username)
    username_pattern.gsub('%s', username)
  end
end

PARAMS = YAML::load_file(File.expand_path('../config.yml', __FILE__))

def valid_password?(password)
  return false if password.length < 8
  return true
end

get "/" do
  erb :index
end

post "/" do
  ldap = LDAP.new(PARAMS)

  if !ldap.valid_login?(params[:username], params[:password])
    @error = "Invalid login/password combination!"
  elsif params[:new_password] != params[:password_confirmation]
    @error = "Password does not match confirmation!"
  elsif !valid_password?(params[:new_password])
    @error = "Invalid password!"
  elsif !ldap.change_password(params[:username], params[:new_password])
    @error = "Changing password failed!"
  else
    @success = "Password changed!"
  end

  erb :index
end

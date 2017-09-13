# == Schema Information
#
# Table name: users
#
#  id         :integer          not null, primary key
#  name       :string(255)
#  email      :string(255)
#  created_at :datetime         not null
#  updated_at :datetime         not null
#
require 'digest'

class User < ActiveRecord::Base
  attr_accessor :password
  attr_accessible :email, :name
  has_many :microposts

  email_regrex = /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i
  validates :name, :presence => true,
                    :length => {maximum: 50}
  validates :email, :presence => true,
                    :format => {:with => email_regrex},
                    :uniqueness => {:case_sensitive => false}

  #validates :password, :presence => true
  #before_save :encrypt_password

  def has_password?(submitted_password)
    encrypted_password == encrypt(submitted_password)
  end

  private
  def encrypted_password
    self.salt = make_salt if new_record?
    self.encrypted_password = encrypt(password)
  end

  def encrypt(string)
    secure_hash("#{salt}--#{string}")
  end

  def secure_hash(string)
    Digest::SHA2.hexdigest(string)
  end

  def make_salt
    secure_hash("#{Time.now.utc}--#{password}")
  end

  #class level method
  def self.authenticate(email, password)
    user = self.find_by_email(email)
    return nil if user.nil?
    return user if user.has_password?(password)
  end
end

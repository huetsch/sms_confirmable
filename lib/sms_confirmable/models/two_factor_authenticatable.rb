module Devise
  module Models
    module SmsConfirmable
      extend ActiveSupport::Concern

      included do
        before_create :generate_confirmation_token, if: :confirmation_required?
        after_create  :send_on_create_confirmation_instructions, if: :send_confirmation_notification?
        before_update :postpone_phone_number_change_until_confirmation_and_regenerate_confirmation_token, if: :postpone_phone_number_change?
        after_update  :send_reconfirmation_instructions,  if: :reconfirmation_required?
      end

      def initialize(*args, &block)
        @bypass_confirmation_postpone = false
        @reconfirmation_required = false
        @skip_confirmation_notification = false
        @raw_confirmation_token = nil
        super
      end

      def self.required_fields(klass)
        required_methods = [:phone_number, :confirmation_token, :confirmed_at, :confirmation_sent_at]
        required_methods << :unconfirmed_phone_number if klass.reconfirmable
        required_methods
      end

      def send_sms_confirmation_code(code, options = {})
        raise NotImplementedError.new("No default implementation - please define in your class.")
      end

      # Confirm a user by setting it's confirmed_at to actual time. If the user
      # is already confirmed, add an error to phone_number field. If the user is invalid
      # add errors
      def confirm!
        pending_any_confirmation do
          if confirmation_period_expired?
            self.errors.add(:phone_number, :confirmation_period_expired,
              period: Devise::TimeInflector.time_ago_in_words(self.class.confirm_within.ago))
            return false
          end

          self.confirmation_token = nil
          self.confirmed_at = Time.now.utc

          saved = if self.class.reconfirmable && unconfirmed_phone_number.present?
            skip_reconfirmation!
            self.phone_number = unconfirmed_phone_number
            self.unconfirmed_phone_number = nil

            # We need to validate in such cases to enforce phone number uniqueness
            save(validate: true)
          else
            save(validate: false)
          end

          after_confirmation if saved
          saved
        end
      end

      def confirmed?
        !!confirmed_at
      end

      def pending_reconfirmation?
        self.class.reconfirmable && unconfirmed_phone_number.present?
      end

      # Send confirmation instructions by sms
      def send_confirmation_instructions
        unless @raw_confirmation_token
          generate_confirmation_token!
        end

        opts = pending_reconfirmation? ? { to: unconfirmed_phone_number } : { }
        send_sms_confirmation_code(@raw_confirmation_token, opts)
      end

      def send_reconfirmation_instructions
        @reconfirmation_required = false

        unless @skip_confirmation_notification
          send_confirmation_instructions
        end
      end

      # Resend confirmation token.
      # Regenerates the token if the period is expired.
      def resend_confirmation_instructions
        pending_any_confirmation do
          send_confirmation_instructions
        end
      end

      # Overwrites active_for_authentication? for confirmation
      # by verifying whether a user is active to sign in or not. If the user
      # is already confirmed, it should never be blocked. Otherwise we need to
      # calculate if the confirm time has not expired for this user.
      def active_for_authentication?
        super && (!confirmation_required? || confirmed? || confirmation_period_valid?)
      end

      # The message to be shown if the account is inactive.
      def inactive_message
        !confirmed? ? :unconfirmed : super
      end

      # If you don't want confirmation to be sent on create, neither a code
      # to be generated, call skip_confirmation!
      def skip_confirmation!
        self.confirmed_at = Time.now.utc
      end

      # Skips sending the confirmation/reconfirmation notification sms after_create/after_update. Unlike
      # #skip_confirmation!, record still requires confirmation.
      def skip_confirmation_notification!
        @skip_confirmation_notification = true
      end

      # If you don't want reconfirmation to be sent, neither a code
      # to be generated, call skip_reconfirmation!
      def skip_reconfirmation!
        @bypass_confirmation_postpone = true
      end

      protected
        def send_on_create_confirmation_instructions
          send_confirmation_instructions
        end

        # Callback to overwrite if confirmation is required or not.
        def confirmation_required?
          !confirmed?
        end

        def confirmation_period_valid?
          self.class.allow_unconfirmed_access_for.nil? || (confirmation_sent_at && confirmation_sent_at.utc >= self.class.allow_unconfirmed_access_for.ago)
        end

        def confirmation_period_expired?
          self.class.confirm_within && (Time.now > self.confirmation_sent_at + self.class.confirm_within )
        end

        # Checks whether the record requires any confirmation.
        def pending_any_confirmation
          if (!confirmed? || pending_reconfirmation?)
            yield
          else
            self.errors.add(:phone_number, :already_confirmed)
            false
          end
        end

        # Generates a new random token for confirmation, and stores
        # the time this token is being generated
        def generate_confirmation_token
          raw, enc = Devise.token_generator.generate(self.class, :confirmation_token)
          @raw_confirmation_token   = raw
          self.confirmation_token   = enc
          self.confirmation_sent_at = Time.now.utc
        end

        def generate_confirmation_token!
          generate_confirmation_token && save(validate: false)
        end

        def postpone_phone_number_change_until_confirmation_and_regenerate_confirmation_token
          @reconfirmation_required = true
          self.unconfirmed_phone_number = self.phone_number
          self.phone_number = self.phone_number_was
          generate_confirmation_token
        end

        def postpone_phone_number_change?
          postpone = self.class.reconfirmable && phone_number_changed? && !@bypass_confirmation_postpone && self.phone_number.present?
          @bypass_confirmation_postpone = false
          postpone
        end

        def reconfirmation_required?
          self.class.reconfirmable && @reconfirmation_required && self.phone_number.present?
        end

        def send_confirmation_notification?
          confirmation_required? && !@skip_confirmation_notification && self.phone_number.present?
        end

        def after_confirmation
        end

      module ClassMethods
        # Attempt to find a user by its phone_number. If a record is found, send new
        # confirmation instructions to it. If not, try searching for a user by unconfirmed_phone_number
        # field. If no user is found, returns a new user with a phone_number not found error.
        # Options must contain the user phone_number
        def send_confirmation_instructions(attributes={})
          confirmable = find_by_unconfirmed_phone_number_with_errors(attributes) if reconfirmable
          unless confirmable.try(:persisted?)
            confirmable = find_or_initialize_with_errors(confirmation_keys, attributes, :not_found)
          end
          confirmable.resend_confirmation_instructions if confirmable.persisted?
          confirmable
        end

        # Find a user by its confirmation token and try to confirm it.
        # If no user is found, returns a new user with an error.
        # If the user is already confirmed, create an error for the user
        # Options must have the confirmation_token
        def confirm_by_token(confirmation_token)
          original_token     = confirmation_token
          confirmation_token = Devise.token_generator.digest(self, :confirmation_token, confirmation_token)

          confirmable = find_or_initialize_with_error_by(:confirmation_token, confirmation_token)
          confirmable.confirm! if confirmable.persisted?
          confirmable.confirmation_token = original_token
          confirmable
        end

        # Find a record for confirmation by unconfirmed phone_number field
        def find_by_unconfirmed_phone_number_with_errors(attributes = {})
          unconfirmed_required_attributes = confirmation_keys.map { |k| k == :phone_number ? :unconfirmed_phone_number : k }
          unconfirmed_attributes = attributes.symbolize_keys
          unconfirmed_attributes[:unconfirmed_phone_number] = unconfirmed_attributes.delete(:phone_number)
          find_or_initialize_with_errors(unconfirmed_required_attributes, unconfirmed_attributes, :not_found)
        end

        Devise::Models.config(self, :allow_unconfirmed_access_for, :confirmation_keys, :reconfirmable, :confirm_within)
      end
    end
  end
end

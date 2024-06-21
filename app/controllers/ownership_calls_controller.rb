class OwnershipCallsController < ApplicationController
  before_action :find_rubygem, except: :index
  before_action :redirect_to_signin, unless: :signed_in?, except: :index
  before_action :redirect_to_new_mfa, if: :mfa_required_not_yet_enabled?, except: :index
  before_action :redirect_to_settings_strong_mfa_required, if: :mfa_required_weak_level_enabled?, except: :index
  before_action :find_ownership_call, only: :close

  def index
    set_page
    @ownership_calls = OwnershipCall.opened.includes(:user, rubygem: %i[latest_version gem_download]).order(created_at: :desc)
      .page(@page)
      .per(Gemcutter::OWNERSHIP_CALLS_PER_PAGE)
  end

  def create
    @ownership_call = authorize @rubygem.ownership_calls.new(user: current_user, note: params[:note])
    if @ownership_call.save
      redirect_to rubygem_adoptions_path(@rubygem.slug), notice: t(".success_notice", gem: @rubygem.name)
    else
      redirect_to rubygem_adoptions_path(@rubygem.slug), alert: @ownership_call.errors.full_messages.to_sentence
    end
  end

  def close
    if @ownership_call.close
      redirect_to rubygem_path(@rubygem.slug), notice: t("ownership_calls.update.success_notice", gem: @rubygem.name)
    else
      redirect_to rubygem_adoptions_path(@rubygem.slug), alert: t("try_again")
    end
  end

  private

  def find_ownership_call
    @ownership_call = @rubygem.ownership_call
    return authorize @ownership_call if @ownership_call
    redirect_to rubygem_adoptions_path(@rubygem.slug), alert: t("try_again")
  end
end

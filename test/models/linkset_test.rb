require "test_helper"

class LinksetTest < ActiveSupport::TestCase
  should belong_to :rubygem

  context "with a linkset" do
    setup do
      @linkset = build(:linkset)
    end

    should "be valid with factory" do
      assert_predicate @linkset, :valid?
    end

    should "not be empty with some links filled out" do
      refute_empty @linkset
    end

    should "be empty with no links filled out" do
      Linkset::LINKS.each do |link|
        @linkset.send("#{link}=", nil)
      end
      assert_empty @linkset
    end

    should "tell whether a link is verified" do
      @linkset.send(:home_verified_at=, Date.current)
      empty_keys = Linkset::LINKS.reject { |k| k == "home" }

      assert @linkset.verified?("home")
      empty_keys.each do |link|
        refute @linkset.verified?(link)
      end
    end
  end

  context "with a Gem::Specification" do
    setup do
      @spec    = gem_specification_from_gem_fixture("test-0.0.0")
      @linkset = create(:linkset)
      @linkset.update_attributes_from_gem_specification!(@spec)
    end

    should "have linkset home be set to the specificaton's homepage" do
      assert_equal @spec.homepage, @linkset.home
    end
  end
end

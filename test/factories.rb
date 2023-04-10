FactoryBot.define do
  factory :oidc_api_key_role, class: "OIDC::ApiKeyRole" do
    provider { build(:oidc_provider) }
    user
    api_key_permissions do
      {
        scopes: ["push_rubygem"]
      }
    end
    name { "GitHub Pusher" }
    access_policy do
      {
        statements: [
          { effect: "allow",
            principal: { oidc: provider.issuer },
            conditions: [] }
        ]
      }
    end
  end

  factory :oidc_provider, class: "OIDC::Provider" do
    issuer { "https://token.actions.githubusercontent.com" }
    configuration do
      {
        issuer: "https://token.actions.githubusercontent.com",
        jwks_uri: "https://token.actions.githubusercontent.com/.well-known/jwks",
        subject_types_supported: %w[
          public
          pairwise
        ],
        response_types_supported: [
          "id_token"
        ],
        claims_supported: %w[
          sub
          aud
          exp
          iat
          iss
          jti
          nbf
          ref
          repository
          repository_id
          repository_owner
          repository_owner_id
          run_id
          run_number
          run_attempt
          actor
          actor_id
          workflow
          workflow_ref
          workflow_sha
          head_ref
          base_ref
          event_name
          ref_type
          environment
          environment_node_id
          job_workflow_ref
          job_workflow_sha
          repository_visibility
          runner_environment
        ],
        id_token_signing_alg_values_supported: [
          "RS256"
        ],
        scopes_supported: [
          "openid"
        ]
      }
    end
    jwks do
      {
        keys: [
          {
            n: "4WpHpoBYsVBVfSlfgnRbdPMxP3Eb7rFqE48e4pPM4qH_9EsUZIi21LjOu8UkKn14L4hrRfzfRHG7VQSbxXBU1Qa-xM5yVxdmfQZKBxQnPWaE1v7edjxq1ZYnqHIp90Uvnw6798xMCSvI_V3FR8tix5GaoTgkixXlPc-ozifMyEZMmhvuhfDsSxQeTSHGPlWfGkX0id_gYzKPeI69EGtQ9ZN3PLTdoAI8jxlQ-jyDchi9h2ax6hgMLDsMZyiIXnF2UYq4j36Cs5RgdC296d0hEOHN0WYZE-xPl7y_A9UHcVjrxeGfVOuTBXqjowofimn4ESnVXNReCsOwZCJlvJzfpQ",
            kty: "RSA",
            kid: "78167F727DEC5D801DD1C8784C704A1C880EC0E1",
            alg: "RS256",
            e: "AQAB",
            use: "sig",
            x5c: [
              "MIIDrDCCApSgAwIBAgIQMPdKi0TFTMqmg1HHo6FfsDANBgkqhkiG9w0BAQsFADA2MTQwMgYDVQQDEyt2c3RzLXZzdHNnaHJ0LWdoLXZzby1vYXV0aC52aXN1YWxzdHVkaW8uY29tMB4XDTIyMDEwNTE4NDcyMloXDTI0MDEwNTE4NTcyMlowNjE0MDIGA1UEAxMrdnN0cy12c3RzZ2hydC1naC12c28tb2F1dGgudmlzdWFsc3R1ZGlvLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOFqR6aAWLFQVX0pX4J0W3TzMT9xG+6xahOPHuKTzOKh//RLFGSIttS4zrvFJCp9eC+Ia0X830Rxu1UEm8VwVNUGvsTOclcXZn0GSgcUJz1mhNb+3nY8atWWJ6hyKfdFL58Ou/fMTAkryP1dxUfLYseRmqE4JIsV5T3PqM4nzMhGTJob7oXw7EsUHk0hxj5VnxpF9Inf4GMyj3iOvRBrUPWTdzy03aACPI8ZUPo8g3IYvYdmseoYDCw7DGcoiF5xdlGKuI9+grOUYHQtvendIRDhzdFmGRPsT5e8vwPVB3FY68Xhn1TrkwV6o6MKH4pp+BEp1VzUXgrDsGQiZbyc36UCAwEAAaOBtTCBsjAOBgNVHQ8BAf8EBAMCBaAwCQYDVR0TBAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwNgYDVR0RBC8wLYIrdnN0cy12c3RzZ2hydC1naC12c28tb2F1dGgudmlzdWFsc3R1ZGlvLmNvbTAfBgNVHSMEGDAWgBRZBaZCR9ghvStfcWaGwuHGjrfTgzAdBgNVHQ4EFgQUWQWmQkfYIb0rX3FmhsLhxo6304MwDQYJKoZIhvcNAQELBQADggEBAGNdfALe6mdxQ67QL8GlW4dfFwvCX87JOeZThZ9uCj1+x1xUnywoR4o5q2DVI/JCvBRPn0BUb3dEVWLECXDHGjblesWZGMdSGYhMzWRQjVNmCYBC1ZM5QvonWCBcGkd72mZx0eFHnJCAP/TqEEpRvMHR+OOtSiZWV9zZpF1tf06AjKwT64F9V8PCmSIqPJXcTQXKKfkHZmGUk9AYF875+/FfzF89tCnT53UEh5BldFz0SAls+NhexbW/oOokBNCVqe+T2xXizktbFnFAFaomvwjVSvIeu3i/0Ygywl+3s5izMEsZ1T1ydIytv4FZf2JCHgRpmGPWJ5A7TpxuHSiE8Do="
            ],
            x5t: "eBZ_cn3sXYAd0ch4THBKHIgOwOE"
          },
          {
            n: "wgCsNL8S6evSH_AHBsps2ccIHSwLpuEUGS9GYenGmGkSKyWefKsZheKl_84voiUgduuKcKA2aWQezp9338LjtlBmTHjopzAeU-Q3_IvqNf7BfrEAzEyp-ymdhNzPTE7Snmr5o_9AeiP1ZDBo35FaULgVUECJ3AzAM36zkURax3VNZRRZx1gb8lPUs9M5Yw6aZpHSOd6q_QzE8CP1OhGrAdoBzZ6ZCElon0kI-IuRLCwKptS7Yroi5-RtEKD2W458axNAQ36Yw93N8kInUC1QZDPrKd4QfYiG68ywjBoxp_bjNg5kh4LJmq1mwyGdNQV6F1Ew_jYlmou2Y8wvHQRJPQ",
            kty: "RSA",
            kid: "52F197C481DE70112C441B4A9B37B53C7FCF0DB5",
            alg: "RS256",
            e: "AQAB",
            use: "sig",
            x5c: [
              "MIIDrDCCApSgAwIBAgIQLQnoXJ3HT6uPYvEofvOZ6zANBgkqhkiG9w0BAQsFADA2MTQwMgYDVQQDEyt2c3RzLXZzdHNnaHJ0LWdoLXZzby1vYXV0aC52aXN1YWxzdHVkaW8uY29tMB4XDTIxMTIwNjE5MDUyMloXDTIzMTIwNjE5MTUyMlowNjE0MDIGA1UEAxMrdnN0cy12c3RzZ2hydC1naC12c28tb2F1dGgudmlzdWFsc3R1ZGlvLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIArDS/Eunr0h/wBwbKbNnHCB0sC6bhFBkvRmHpxphpEislnnyrGYXipf/OL6IlIHbrinCgNmlkHs6fd9/C47ZQZkx46KcwHlPkN/yL6jX+wX6xAMxMqfspnYTcz0xO0p5q+aP/QHoj9WQwaN+RWlC4FVBAidwMwDN+s5FEWsd1TWUUWcdYG/JT1LPTOWMOmmaR0jneqv0MxPAj9ToRqwHaAc2emQhJaJ9JCPiLkSwsCqbUu2K6IufkbRCg9luOfGsTQEN+mMPdzfJCJ1AtUGQz6yneEH2IhuvMsIwaMaf24zYOZIeCyZqtZsMhnTUFehdRMP42JZqLtmPMLx0EST0CAwEAAaOBtTCBsjAOBgNVHQ8BAf8EBAMCBaAwCQYDVR0TBAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwNgYDVR0RBC8wLYIrdnN0cy12c3RzZ2hydC1naC12c28tb2F1dGgudmlzdWFsc3R1ZGlvLmNvbTAfBgNVHSMEGDAWgBTTNQQWmG4PZZsdfMeamCH1YcyDZTAdBgNVHQ4EFgQU0zUEFphuD2WbHXzHmpgh9WHMg2UwDQYJKoZIhvcNAQELBQADggEBAK/d+HzBSRac7p6CTEolRXcBrBmmeJUDbBy20/XA6/lmKq73dgc/za5VA6Kpfd6EFmG119tl2rVGBMkQwRx8Ksr62JxmCw3DaEhE8ZjRARhzgSiljqXHlk8TbNnKswHxWmi4MD2/8QhHJwFj3X35RrdMM4R0dN/ojLlWsY9jXMOAvcSBQPBqttn/BjNzvn93GDrVafyX9CPl8wH40MuWS/gZtXeYIQg5geQkHCyP96M5Sy8ZABOo9MSIfPRw1F7dqzVuvliul9ZZGV2LsxmZCBtbsCkBau0amerigZjud8e9SNp0gaJ6wGhLbstCZIdaAzS5mSHVDceQzLrX2oe1h4k="
            ],
            x5t: "UvGXxIHecBEsRBtKmze1PH_PDbU"
          }
        ]
      }
    end
  end

  factory :admin_github_user, class: "Admin::GitHubUser" do
    login { "jackson-keeling" }
    avatar_url { "MyString" }
    sequence(:github_id, &:to_s)

    oauth_token { SecureRandom.hex(10) }
    is_admin { false }
    info_data { { viewer: { login: login, id: github_id } } }

    trait :is_admin do
      is_admin { true }
      info_data do
        {
          viewer: {
            login: login,
            id: github_id,
            organization: {
              name: "RubyGems",
              login: "rubygems",
              viewerIsAMember: true,
              teams: {
                edges: [
                  { node: { slug: "rubygems-org" } },
                  { node: { slug: "security" } }
                ]
              }
            }
          }
        }
      end
    end
  end

  sequence :email do |n|
    "user#{n}@example.com"
  end

  sequence :handle do |n|
    "handle#{n}"
  end

  factory :user do
    email
    handle
    password { PasswordHelpers::SECURE_TEST_PASSWORD }
    api_key { "secret123" }
    email_confirmed { true }

    trait :mfa_enabled do
      mfa_seed { "123abc" }
      mfa_level { User.mfa_levels["ui_and_api"] }
      mfa_recovery_codes { %w[aaa bbb ccc] }
    end
  end

  factory :dependency do
    gem_dependency do
      rubygem = Rubygem.last || create(:rubygem)
      Gem::Dependency.new(rubygem.name, "1.0.0")
    end

    rubygem
    version

    trait :runtime

    trait :development do
      gem_dependency do
        rubygem = Rubygem.last || create(:rubygem)
        Gem::Dependency.new(rubygem.name, "1.0.0", :development)
      end
    end

    trait :unresolved do
      gem_dependency { Gem::Dependency.new("unresolved-gem-nothere", "1.0.0") }
      rubygem { nil }
    end
  end

  factory :linkset do
    rubygem
    home { "http://example.com" }
    wiki { "http://example.com" }
    docs { "http://example.com" }
    mail { "http://example.com" }
    code { "http://example.com" }
    bugs { "http://example.com" }
  end

  factory :ownership do
    rubygem
    user
    confirmed_at { Time.current }
    authorizer { user }
    trait :unconfirmed do
      confirmed_at { nil }
    end
  end

  factory :ownership_call do
    rubygem
    user
    note { "small note" }
    trait :closed do
      status { "closed" }
    end
  end

  factory :ownership_request do
    rubygem
    user
    note { "small note here" }
    status { "opened" }
    approver { nil }
    trait :approved do
      approver { user }
      status { "approved" }
    end
    trait :closed do
      status { "closed" }
    end
    trait :with_ownership_call do
      ownership_call
    end
  end

  factory :subscription do
    rubygem
    user
  end

  factory :api_key do
    transient { key { "12345" } }

    user
    name { "ci-key" }

    # enabled by default. disabled when show_dashboard is enabled.
    index_rubygems { show_dashboard ? false : true }

    hashed_key { Digest::SHA256.hexdigest(key) }
  end

  sequence :name do |n|
    "RubyGem#{n}"
  end

  factory :rubygem do
    transient do
      owners { [] }
      number { nil }
      downloads { 0 }
    end

    name

    after(:build) do |rubygem, evaluator|
      if evaluator.linkset
        rubygem.linkset = evaluator.linkset
      else
        build(:linkset, rubygem: rubygem)
      end
    end

    after(:create) do |rubygem, evaluator|
      evaluator.owners.each do |owner|
        create(:ownership, rubygem: rubygem, user: owner)
      end

      create(:version, rubygem: rubygem, number: evaluator.number) if evaluator.number
      GemDownload.increment(evaluator.downloads, rubygem_id: rubygem.id, version_id: 0) if evaluator.downloads
    end
  end

  sequence :number do |n|
    "0.0.#{n}"
  end

  factory :version do
    authors { ["Joe User"] }
    built_at { 1.day.ago }
    description { "Some awesome gem" }
    indexed { true }
    metadata { { "foo" => "bar" } }
    number
    canonical_number { Gem::Version.new(number).canonical_segments.join(".") }
    platform { "ruby" }
    required_rubygems_version { ">= 2.6.3" }
    required_ruby_version { ">= 2.0.0" }
    licenses { "MIT" }
    requirements { "Opencv" }
    rubygem
    size { 1024 }
    # In reality sha256 is different for different version
    # sha256 is calculated in Pusher, we don't use pusher to create versions in tests
    sha256 { "tdQEXD9Gb6kf4sxqvnkjKhpXzfEE96JucW4KHieJ33g=" }

    trait :yanked do
      indexed { false }
    end

    trait :mfa_required do
      metadata { { "rubygems_mfa_required" => "true" } }
    end
  end

  sequence :url do |n|
    "http://example#{n}.com"
  end

  factory :web_hook do
    rubygem
    url
    user

    factory :global_web_hook do
      rubygem { nil }
    end
  end

  factory :gem_download do
    rubygem_id { 0 }
    version_id { 0 }
    count { 0 }
  end

  factory :sendgrid_event do
    sequence(:sendgrid_id) { |n| "TestSendgridId#{n}" }
    status { "pending" }
    payload { {} }
  end

  factory :gem_typo_exception do
    name
  end

  factory :webauthn_credential do
    user
    sequence(:external_id) { |n| "webauthn-credential-#{n}" }
    public_key { "abc" }
    nickname { "Key #{SecureRandom.hex(24)}" }

    trait :primary

    trait :backup do
      nickname { "Backup key" }
    end
  end

  factory :webauthn_verification do
    user
    path_token { SecureRandom.base58(16) }
    path_token_expires_at { Time.now.utc + 2.minutes }
    otp { SecureRandom.base58(16) }
    otp_expires_at { Time.now.utc + 2.minutes }
  end

  factory :api_key_rubygem_scope do
    ownership
    api_key { create(:api_key, key: SecureRandom.hex(24)) }
  end

  factory :audit do
    admin_github_user

    comment { "A nice long comment" }
    action { "Admin Action" }
    auditable { build(:web_hook) }

    transient do
      records do
        {}
      end

      fields do
        { "field1" => "field1value", "field2" => %w[a b c] }
      end

      arguments do
        { "argument1" => true }
      end

      models do
        []
      end
    end

    after :create do |audit, options|
      audit.update(audited_changes: { records: options.records, fields: options.fields, arguments: options.arguments, models: options.models })
    end
  end

  factory :log_ticket do
    sequence(:key) { "key-#{_1}" }
    sequence(:directory) { "directory-#{_1}" }
    status { :pending }
  end
end

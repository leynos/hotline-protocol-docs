Feature: Wireframe login compatibility
  Successful login replies include fields 161 and 162 regardless of reported
  client version or shared handshake sub-version 2.

  Scenario: Hotline 1.8.5 login reply includes banner fields
    Given a routing context with user accounts
    And a handshake sub-version 0
    When I send a login request with client version 151
    Then the login reply includes banner fields

  Scenario: Hotline 1.9 login reply includes banner fields
    Given a routing context with user accounts
    And a handshake sub-version 0
    When I send a login request with client version 190
    Then the login reply includes banner fields

  Scenario: Sub-version 2 login reply includes fields
    Given a routing context with user accounts
    And a handshake sub-version 2
    When I send a login request with client version 190
    Then the login reply includes banner fields

  Scenario: Reported version 100 still includes fields
    Given a routing context with user accounts
    And a handshake sub-version 0
    When I send a login request with client version 100
    Then the login reply includes banner fields

  Scenario: Reported version 150 still includes fields
    Given a routing context with user accounts
    And a handshake sub-version 0
    When I send a login request with client version 150
    Then the login reply includes banner fields

  Scenario: Sub-version 2 with reported version 151 includes fields
    Given a routing context with user accounts
    And a handshake sub-version 2
    When I send a login request with client version 151
    Then the login reply includes banner fields

  Scenario: Login failure does not add banner fields
    Given a routing context with user accounts
    And a handshake sub-version 0
    When I send a login request with invalid credentials and client version 190
    Then the login reply fails without banner fields

  Scenario: Maximum login version includes banner fields for Hotline clients
    Given a routing context with user accounts
    And a handshake sub-version 0
    When I send a login request with client version 65535
    Then the login reply includes banner fields

  Scenario: Sub-version 2 with max reported version includes fields
    Given a routing context with user accounts
    And a handshake sub-version 2
    When I send a login request with client version 65535
    Then the login reply includes banner fields

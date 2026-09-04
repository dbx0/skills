# VRT P1 / P2 entries (release 2026-07-08)

Scan list for the critical/high end of the taxonomy. Everything else: `scripts/vrt.py search`.

## P1

| id-path | CWE |
|---|---|
| `ai_application_security.model_extraction.api_query_based_model_reconstruction` | - |
| `ai_application_security.remote_code_execution.full_system_compromise` | - |
| `ai_application_security.sensitive_information_disclosure.cross_tenant_pii_leakage_exposure` | - |
| `ai_application_security.sensitive_information_disclosure.key_leak` | - |
| `ai_application_security.training_data_poisoning.backdoor_injection_bias_manipulation` | - |
| `automotive_security_misconfiguration.infotainment_radio_head_unit.sensitive_data_leakage_exposure` | - |
| `automotive_security_misconfiguration.rf_hub.key_fob_cloning` | - |
| `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` | CWE-932 |
| `broken_authentication_and_session_management.authentication_bypass` | CWE-287 |
| `cloud_security.identity_and_access_management_iam_misconfigurations.publicly_accessible_iam_credentials` | - |
| `decentralized_application_misconfiguration.insecure_data_storage.plaintext_private_key` | - |
| `decentralized_application_misconfiguration.marketplace_security.orderbook_manipulation` | - |
| `decentralized_application_misconfiguration.marketplace_security.signer_account_takeover` | - |
| `decentralized_application_misconfiguration.marketplace_security.unauthorized_asset_transfer` | - |
| `decentralized_application_misconfiguration.protocol_security_misconfiguration.node_level_denial_of_service` | - |
| `insecure_os_firmware.command_injection` | CWE-77 |
| `insecure_os_firmware.hardcoded_password.privileged_user` | CWE-259 |
| `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` | CWE-934 |
| `server_security_misconfiguration.exposed_portal.admin_portal` | CWE-16 |
| `server_security_misconfiguration.using_default_credentials` | CWE-255,CWE-521 |
| `server_side_injection.file_inclusion.local` | CWE-73,CWE-714 |
| `server_side_injection.remote_code_execution_rce` | CWE-77,CWE-78,CWE-94,CWE-95 |
| `server_side_injection.sql_injection` | CWE-89 |
| `server_side_injection.xml_external_entity_injection_xxe` | CWE-611 |
| `smart_contract_misconfiguration.reentrancy_attack` | - |
| `smart_contract_misconfiguration.smart_contract_owner_takeover` | - |
| `smart_contract_misconfiguration.unauthorized_transfer_of_funds` | - |
| `smart_contract_misconfiguration.uninitialized_variables` | - |
| `zero_knowledge_security_misconfiguration.deanonymization_of_data` | - |
| `zero_knowledge_security_misconfiguration.improper_proof_validation_and_finalization_logic` | - |
| `active_directory.kerberos_abuse.domain_compromise_unconstrained_delegated` | - |

## P2

| id-path | CWE |
|---|---|
| `ai_application_security.denial_of_service_dos.application_wide` | - |
| `ai_application_security.prompt_injection.system_prompt_leakage` | - |
| `ai_application_security.remote_code_execution.sandboxed_container_code_execution` | - |
| `ai_application_security.vector_and_embedding_weaknesses.embedding_exfiltration_model_extraction` | - |
| `application_level_denial_of_service_dos.critical_impact_and_or_easy_difficulty` | CWE-400 |
| `automotive_security_misconfiguration.infotainment_radio_head_unit.code_execution_can_bus_pivot` | - |
| `automotive_security_misconfiguration.infotainment_radio_head_unit.ota_firmware_manipulation` | - |
| `automotive_security_misconfiguration.rf_hub.can_injection_interaction` | - |
| `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` | CWE-932 |
| `cloud_security.identity_and_access_management_iam_misconfigurations.overly_permissive_iam_roles` | - |
| `cloud_security.storage_misconfigurations.unencrypted_sensitive_data_at_rest` | - |
| `cross_site_request_forgery_csrf.application_wide` | CWE-352 |
| `cross_site_scripting_xss.stored.non_admin_to_anyone` | CWE-79 |
| `cryptographic_weakness.key_reuse.inter_environment` | CWE-323 |
| `decentralized_application_misconfiguration.marketplace_security.malicious_order_offer` | - |
| `decentralized_application_misconfiguration.marketplace_security.price_or_fee_manipulation` | - |
| `insecure_os_firmware.hardcoded_password.non_privileged_user` | CWE-259 |
| `insecure_os_firmware.local_administrator_on_default_environment` | CWE-276 |
| `insecure_os_firmware.over_permissioned_credentials_on_storage` | CWE-250 |
| `physical_security_issues.weakness_in_physical_access_control.commonly_keyed_system` | CWE-284 |
| `protocol_specific_misconfiguration.frontrunning_enabled_attack` | - |
| `protocol_specific_misconfiguration.sandwich_enabled_attack` | - |
| `sensitive_data_exposure.weak_password_reset_implementation.token_leakage_via_host_header_poisoning` | CWE-640 |
| `server_security_misconfiguration.oauth_misconfiguration.account_takeover` | CWE-303 |
| `server_security_misconfiguration.server_side_request_forgery_ssrf.internal_secrets_exposure` | CWE-918,CWE-441 |
| `smart_contract_misconfiguration.integer_overflow_underflow` | - |
| `smart_contract_misconfiguration.unauthorized_smart_contract_approval` | - |
| `active_directory.kerberos_abuse.insecure_service_account_management` | - |
| `active_directory.kerberos_abuse.no_pre_authentication` | - |
| `active_directory.configuration_weaknesses.weak_domain_password_policy` | - |
| `active_directory.configuration_weaknesses.shared_administrator_passwords` | - |

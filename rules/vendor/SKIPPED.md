# Pack decision 2026-10-23

No vendor rule body is committed. yara-forge core contains at least one `NO LICENSE SET` rule. signature-base meta cites Detection Rule License 1.1, and that license text was not fetched. Elastic stays under Elastic License 2.0 and is not packaged for redistribution. The lock pins are unchanged. A per-rule false-positive census was not run. `rules install` rewrites this file from compile skips, so the durable copy of this decision is `docs/verification/vendor-pack-review.md`.

# Rules skipped because yara-x could not compile them

configured_vulns_ext_vars.yar: CompileError
expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar: CompileError
expl_connectwise_screenconnect_vuln_feb24.yar: CompileError
gen_fake_amsi_dll.yar: CompileError
gen_mal_3cx_compromise_mar23.yar: CompileError
gen_susp_obfuscation.yar: CompileError
gen_vcruntime140_dll_sideloading.yar: CompileError
gen_webshells_ext_vars.yar: CompileError
general_cloaking.yar: CompileError
generic_anomalies.yar: CompileError
thor_inverse_matches.yar: CompileError
yara-rules_vuln_drivers_strict_renamed.yar: CompileError
yara_mixed_ext_vars.yar: CompileError

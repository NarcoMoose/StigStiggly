#!/bin/zsh
# Fake compliance script for StigStiggly UI testing. Emits scan/fix-like output
# slowly, never touches real system state.
rules=(audit_auditd_enabled os_sip_enable os_gatekeeper_enable icloud_drive_disable pwpolicy_max_lifetime_enforce system_settings_bluetooth_sharing_disable)
case "$1" in
  --check)
    for r in $rules; do
      echo "Running the command to check the settings for: $r ..."
      sleep 0.5
    done
    echo ""
    echo "Number of tests passed: 4"
    echo "Number of test FAILED: 2"
    exit 0
    ;;
  --fix)
    echo "$(date -u) Beginning remediation of non-compliant settings"
    for r in ${rules[1,2]}; do
      echo "Running the commands to fix: $r ..."
      sleep 0.6
    done
    exit 0
    ;;
  *)
    echo "usage: $0 --check|--fix" >&2
    exit 2
    ;;
esac

#!/bin/bash
# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Automated refactor: Enum variants → String constants
# Usage: ./tools/refactor_enums_to_strings.sh
#
# This script automates the mechanical transformation from closed enums
# to open string wrappers. Review changes before committing.

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "=== ProofEngine Extensibility Refactor ==="
echo "Converting closed enums to open string wrappers..."
echo

# Safety check
if [ ! -f "Cargo.toml" ] || [ ! -d "crates/proof-core" ]; then
    echo "ERROR: Run this script from the repository root"
    exit 1
fi

# Backup
echo "[1/6] Creating backup..."
BACKUP_DIR="/tmp/proof-engine-backup-$(date +%s)"
mkdir -p "$BACKUP_DIR"
cp -r crates "$BACKUP_DIR/"
echo "    Backup: $BACKUP_DIR"
echo

# EventType transformations
echo "[2/6] Refactoring EventType..."
find crates -name "*.rs" -type f -exec sed -i.bak \
    -e 's/EventType::PaymentCreated/EventType::PAYMENT_CREATED/g' \
    -e 's/EventType::PaymentCompleted/EventType::PAYMENT_COMPLETED/g' \
    -e 's/EventType::InvoiceIssued/EventType::INVOICE_ISSUED/g' \
    -e 's/EventType::DocumentSigned/EventType::DOCUMENT_SIGNED/g' \
    -e 's/EventType::PackageShipped/EventType::PACKAGE_SHIPPED/g' \
    -e 's/EventType::SensorMeasurementRecorded/EventType::SENSOR_MEASUREMENT_RECORDED/g' \
    -e 's/EventType::AiActionExecuted/EventType::AI_ACTION_EXECUTED/g' \
    {} \;
echo "    EventType variants → constants"

# EvidenceKind transformations
echo "[3/6] Refactoring EvidenceKind..."
find crates -name "*.rs" -type f -exec sed -i.bak \
    -e 's/EvidenceKind::SignedEvent/EvidenceKind::SIGNED_EVENT/g' \
    -e 's/EvidenceKind::SignedDocument/EvidenceKind::SIGNED_DOCUMENT/g' \
    -e 's/EvidenceKind::Receipt/EvidenceKind::RECEIPT/g' \
    -e 's/EvidenceKind::Credential/EvidenceKind::CREDENTIAL/g' \
    -e 's/EvidenceKind::Measurement/EvidenceKind::MEASUREMENT/g' \
    -e 's/EvidenceKind::TransactionRecord/EvidenceKind::TRANSACTION_RECORD/g' \
    -e 's/EvidenceKind::TransparencyReceipt/EvidenceKind::TRANSPARENCY_RECEIPT/g' \
    -e 's/EvidenceKind::DeviceAttestation/EvidenceKind::DEVICE_ATTESTATION/g' \
    -e 's/EvidenceKind::ExternalReference/EvidenceKind::EXTERNAL_REFERENCE/g' \
    {} \;
echo "    EvidenceKind variants → constants"

# RelType transformations
echo "[4/6] Refactoring RelType..."
find crates -name "*.rs" -type f -exec sed -i.bak \
    -e 's/RelType::Owns/RelType::OWNS/g' \
    -e 's/RelType::Created/RelType::CREATED/g' \
    -e 's/RelType::Settles/RelType::SETTLES/g' \
    -e 's/RelType::References/RelType::REFERENCES/g' \
    -e 's/RelType::Contains/RelType::CONTAINS/g' \
    -e 's/RelType::Produced/RelType::PRODUCED/g' \
    -e 's/RelType::Executed/RelType::EXECUTED/g' \
    -e 's/RelType::Issued/RelType::ISSUED/g' \
    -e 's/RelType::Supersedes/RelType::SUPERSEDES/g' \
    -e 's/RelType::Revokes/RelType::REVOKES/g' \
    {} \;
echo "    RelType variants → constants"

# Clean up .bak files
echo "[5/6] Cleaning up..."
find crates -name "*.rs.bak" -type f -delete
echo "    Removed backup files"

# Verification
echo "[6/6] Verification..."
if cargo check --all-targets 2>/dev/null; then
    echo "    ✓ cargo check passed"
else
    echo "    ✗ cargo check failed - manual fixes needed"
    echo "    Backup available at: $BACKUP_DIR"
fi
echo

# Summary
echo "=== Refactor Summary ==="
echo "Transformed:"
echo "  - EventType enum variants → string constants"
echo "  - EvidenceKind enum variants → string constants"
echo "  - RelType enum variants → string constants"
echo
echo "Next steps:"
echo "  1. Review changes: git diff"
echo "  2. Update proof-core/src/model.rs with open string types"
echo "  3. Update proof-format parsers (remove None → error)"
echo "  4. Add policy requirements (EventTypePresent, etc.)"
echo "  5. Run tests: cargo test"
echo "  6. Update documentation"
echo
echo "Backup location: $BACKUP_DIR"
echo "Rollback: cp -r $BACKUP_DIR/crates ."

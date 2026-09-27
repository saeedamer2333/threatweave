"""Unit tests for target_detect.py - host paths from the container's own
mounts, and what to scan from the mounted project."""
from __future__ import annotations

import json
from pathlib import Path

import target_detect as td

CFN = '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {}}'
CDK = '{"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}, "Parameters": {}}'


def _write(root: Path, rel: str, text: str = "x") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


# ---------------------------------------------------------------- host paths
def test_windows_mount_sources_become_forward_slash_host_paths():
    assert td.to_host_path("D:\\FYP\\Modules Of sem 6\\Claude") == "D:/FYP/Modules Of sem 6/Claude"
    assert td.to_host_path("/home/me/app/") == "/home/me/app"


def test_results_only_mount_gives_its_parent_as_host_workspace():
    mounts = [
        {"Source": "D:\\threatweave\\accesshub\\findings", "Destination": "/workspace/findings"},
        {"Source": "D:\\code\\AccessHub", "Destination": "/target"},
        {"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"},
    ]
    assert td.host_paths(mounts) == {
        "HOST_WORKSPACE": "D:/threatweave/accesshub",
        "TARGET_PATH": "D:/code/AccessHub",
    }


def test_a_full_workspace_mount_wins_over_a_findings_mount():
    mounts = [
        {"Source": "/srv/threatweave", "Destination": "/workspace"},
        {"Source": "/srv/other/findings", "Destination": "/workspace/findings"},
    ]
    assert td.host_paths(mounts)["HOST_WORKSPACE"] == "/srv/threatweave"


def test_nothing_mounted_means_no_host_paths():
    assert td.host_paths([{"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}]) == {}


# ------------------------------------------------------------- what to scan
def test_empty_target_suggests_nothing(tmp_path):
    result = td.detect_targets(str(tmp_path))
    assert result["sourceDir"] == ""
    assert result["iacCandidates"] == []


def test_detects_cdk_output_and_project_name_like_accesshub(tmp_path):
    _write(tmp_path, ".git/HEAD")
    _write(tmp_path, "package.json", json.dumps({"name": "accesshub"}))
    _write(tmp_path, "backend/src/index.ts")
    _write(tmp_path, "infra/cdk.json", '{"app": "npx ts-node bin/infra.ts"}')
    for stack in ("InfraStack", "ServerlessStack", "UploadStack"):
        _write(tmp_path, f"infra/cdk.out/{stack}.template.json", CDK)
    _write(tmp_path, "infra/cdk.out/asset.abc123/index.template.json", CDK)  # bundled code, not a stack

    result = td.detect_targets(str(tmp_path))

    assert result["sourceDir"] == tmp_path.as_posix()
    assert result["projectName"] == "accesshub"
    assert result["iacDir"] == (tmp_path / "infra" / "cdk.out").as_posix()
    assert result["iacCandidates"][0] == {"path": result["iacDir"], "kind": "cdk", "files": 3}


def test_finds_iac_in_an_unusual_folder_not_named_infra(tmp_path):
    _write(tmp_path, ".git/HEAD")
    _write(tmp_path, "src/app.py")
    _write(tmp_path, "deploy/aws/terraform/main.tf", 'resource "aws_s3_bucket" "b" {}')
    _write(tmp_path, "deploy/aws/terraform/vars.tf", "")

    result = td.detect_targets(str(tmp_path))

    assert result["iacDir"] == (tmp_path / "deploy" / "aws" / "terraform").as_posix()
    assert result["iacCandidates"][0]["kind"] == "terraform"


def test_lists_every_iac_folder_best_first_when_there_are_several(tmp_path):
    _write(tmp_path, ".git/HEAD")
    for n in range(3):
        _write(tmp_path, f"stacks/cfn/stack{n}.yaml", "AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")
    _write(tmp_path, "legacy/tf/main.tf")

    cands = td.detect_targets(str(tmp_path))["iacCandidates"]

    assert [c["kind"] for c in cands] == ["cloudformation", "terraform"]
    assert cands[0]["files"] == 3


def test_ignores_dependencies_and_ordinary_json(tmp_path):
    _write(tmp_path, ".git/HEAD")
    _write(tmp_path, "package.json", json.dumps({"name": "web"}))
    _write(tmp_path, "tsconfig.json", "{}")
    _write(tmp_path, "node_modules/some-lib/main.tf")
    _write(tmp_path, "node_modules/aws-cdk-lib/x.template.json", CFN)

    assert td.detect_targets(str(tmp_path))["iacCandidates"] == []


def test_uses_the_single_repository_inside_a_wrapper_folder(tmp_path):
    _write(tmp_path, "juice-shop/.git/HEAD")
    _write(tmp_path, "juice-shop/package.json", json.dumps({"name": "juice-shop"}))

    result = td.detect_targets(str(tmp_path))

    assert result["sourceDir"] == (tmp_path / "juice-shop").as_posix()
    assert result["projectName"] == "juice-shop"


def test_project_name_falls_back_to_the_host_folder_name(tmp_path):
    _write(tmp_path, ".git/HEAD")
    _write(tmp_path, "main.go")
    assert td.detect_targets(str(tmp_path), host_target="D:/code/My Service")["projectName"] == "My-Service"


# ---------------------------------------------------------------- check
def test_check_accepts_a_real_iac_folder(tmp_path):
    _write(tmp_path, "deploy/main.tf")
    result = td.check_path("iac", str(tmp_path / "deploy"), allowed=(str(tmp_path),))
    assert result["level"] == "ok"
    assert "1 Terraform" in result["message"]


def test_check_catches_a_typo(tmp_path):
    result = td.check_path("iac", str(tmp_path / "deply"), allowed=(str(tmp_path),))
    assert result["ok"] is False
    assert "does not exist" in result["message"]


def test_check_warns_when_a_folder_has_no_iac(tmp_path):
    _write(tmp_path, "docs/readme.md")
    result = td.check_path("iac", str(tmp_path / "docs"), allowed=(str(tmp_path),))
    assert result["level"] == "warn"


def test_check_refuses_paths_outside_the_project(tmp_path):
    result = td.check_path("source", "/etc", allowed=(str(tmp_path),))
    assert result["ok"] is False


def test_check_warns_that_gitleaks_needs_git_history(tmp_path):
    _write(tmp_path, "src/app.js")
    result = td.check_path("source", str(tmp_path), allowed=(str(tmp_path),))
    assert result["level"] == "warn"
    assert "Git" in result["message"]


def test_check_says_empty_means_skipped():
    assert td.check_path("iac", "")["level"] == "info"


# ---------------------------------------------------------------- startup
def test_startup_fills_only_what_the_user_did_not_pass(tmp_path):
    _write(tmp_path, ".git/HEAD")
    _write(tmp_path, "package.json", json.dumps({"name": "accesshub"}))
    _write(tmp_path, "infra/cdk.out/Stack.template.json", CDK)
    mounts = [
        {"Source": "D:\\tw\\accesshub\\findings", "Destination": "/workspace/findings"},
        {"Source": "D:\\code\\AccessHub", "Destination": "/target"},
    ]

    out = td.startup_env(environ={"SCAN_SONAR_KEY": "my-own-key"}, mounts=mounts, root=str(tmp_path))

    assert out["HOST_WORKSPACE"] == "D:/tw/accesshub"
    assert out["TARGET_PATH"] == "D:/code/AccessHub"
    assert out["SCAN_SOURCE_DIR"] == tmp_path.as_posix()
    assert out["SCAN_IAC_DIR"] == (tmp_path / "infra" / "cdk.out").as_posix()
    assert "SCAN_SONAR_KEY" not in out                       # the user's value wins
    assert out["SCAN_DETECTED"] == "SCAN_SOURCE_DIR,SCAN_IAC_DIR"


def test_startup_respects_an_explicitly_empty_value(tmp_path):
    _write(tmp_path, ".git/HEAD")
    _write(tmp_path, "infra/main.tf")
    out = td.startup_env(environ={"HOST_WORKSPACE": "/h", "TARGET_PATH": "/t", "SCAN_IAC_DIR": ""},
                         mounts=[], root=str(tmp_path))
    assert "SCAN_IAC_DIR" not in out                         # -e SCAN_IAC_DIR= means "skip Checkov"


def test_startup_with_nothing_mounted_detects_no_targets(tmp_path):
    assert td.startup_env(environ={"HOST_WORKSPACE": "/h", "TARGET_PATH": "/t"}, mounts=[], root=str(tmp_path)) == {}

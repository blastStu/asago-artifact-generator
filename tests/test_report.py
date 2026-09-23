"""HTML report rendering tests."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from asago_artifact_generator.report import render_report


class TestReport(unittest.TestCase):
    def test_report_combines_input_artifact_and_run_log(self):
        repo = Path(__file__).resolve().parents[1]
        source = repo / "examples" / "scenarios" / "AP-T2-01-28712e.yaml"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scenarios = root / "scenarios"
            runs = root / "runs"
            scenarios.mkdir()
            shutil.copyfile(source, scenarios / source.name)
            other_source = scenarios / "AP-T17-01-00d278.yaml"
            other_source.write_text(
                source.read_text(encoding="utf-8").replace("AP-T2-01-28712e", "AP-T17-01-00d278"),
                encoding="utf-8",
            )
            artifact_dir = runs / "AP-T2-01-28712e"
            artifact_dir.mkdir(parents=True)
            artifact = {
                "scenario_id": "AP-T2-01-28712e",
                "injection_surface": "user_turn",
                "platform_coverage": "full",
                "disclosure": "This artifact contains AI generated content",
                "model": "test-model",
                "timestamp": "2026-01-01T00:00:00Z",
                "narrative": {"summary": "A report summary."},
                "turns": [
                    {"role": "system", "content": "- tool(id): description"},
                    {"role": "user", "content": "<script>alert(1)</script>", "adversarial": True},
                ],
                "attack_turn_index": 1,
                "detector_rubric": {
                    "judge_prompt": "Judge the next response.",
                    "context": "The verified context.",
                    "rubrics": {
                        "attack_success": ["emits the unsafe action"],
                        "attack_blocked": ["declines the unsafe action"],
                    },
                },
            }
            artifact_path = artifact_dir / "AP-T2-01-28712e-garak.json"
            artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
            (artifact_dir / "validation.json").write_text(
                json.dumps({"ok": True, "errors": [], "checks": "checks"}),
                encoding="utf-8",
            )
            (runs / "manifest.json").write_text(
                json.dumps(
                    [
                        {
                            "scenario_id": "AP-T2-01-28712e",
                            "ok": True,
                            "gate_result": "full",
                            "artifact_path": str(artifact_path),
                        }
                    ]
                ),
                encoding="utf-8",
            )
            log_dir = runs / "generation-log"
            log_dir.mkdir()
            (log_dir / "20260101T000000Z.json").write_text(
                json.dumps(
                    {
                        "run_id": "20260101T000000Z",
                        "settings": {
                            "provider": "openai",
                            "model": "test-model",
                            "max_completion_tokens": 16000,
                        },
                        "scenarios": [
                            {
                                "scenario_id": "AP-T2-01-28712e",
                                "status": "success",
                                "attempts": 1,
                                "duration_seconds": 1.2,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            report = render_report(scenarios_dir=scenarios, runs_dir=runs)

        self.assertIn("Artifact generation report", report)
        self.assertIn("What this means:", report)
        self.assertIn("test-model", report)
        self.assertIn("max_completion_tokens", report)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", report)
        self.assertNotIn("<script>alert(1)</script>", report)
        self.assertIn("AP-T2-01-28712e", report)
        self.assertNotIn("AP-T17-01-00d278", report)
        self.assertIn("Scenarios in this run", report)


if __name__ == "__main__":
    unittest.main()

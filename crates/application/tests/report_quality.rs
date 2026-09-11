use aegis_application::report;
use aegis_domain::*;
use serde_json::{Value, json};

struct Fixture {
    project: Project,
    snapshot: Snapshot,
    run: AuditRun,
    units: Vec<ProgramUnit>,
    artifacts: Vec<Artifact>,
    audit: AuditEvidence,
}
const SNAPSHOT_AT: &str = "2026-09-12T03:00:00.000Z";
const CODE: &str = "if (length > 32) {\n    reject(\"<unsafe> | value\");\n}\n";
fn reference(quote: &str) -> EvidenceRef {
    EvidenceRef {
        unit_id: "unit-1".into(),
        artifact_id: "source".into(),
        path: "src/parse.c".into(),
        start_line: 12,
        end_line: 15,
        address: "0x401000".into(),
        quote: quote.into(),
    }
}
fn finding(id: &str, severity: &str, verdict: &str) -> Finding {
    Finding {
        id: id.into(),
        run_id: "run".into(),
        fingerprint: id.into(),
        created_at: "2026-09-12T00:10:00.000Z".into(),
        model_call_id: "call".into(),
        revision: 1,
        review_status: verdict.into(),
        verification_status: "NOT_RUN".into(),
        static_scope: "COMPONENT".into(),
        draft: FindingDraft {
            title: id.into(),
            category: "MEMORY_BOUNDS".into(),
            cwe: "CWE-787".into(),
            severity: severity.into(),
            severity_reason: "SEVERITY-REASON".into(),
            unit_id: "unit-1".into(),
            input_source: "第一段输入\n第二段输入".into(),
            sink: "copy()".into(),
            missing_guard: "MISSING-GUARD".into(),
            preconditions: "PRECONDITIONS".into(),
            impact: "IMPACT".into(),
            recommendation: "RECOMMENDATION".into(),
            evidence: vec![],
        },
        evidence: vec![reference(CODE)],
    }
}
fn fixture() -> Fixture {
    let audit = AuditEvidence {
        findings: vec![
            finding("VALIDATED-ISSUE", "HIGH", "VALIDATED"),
            finding("REJECTED-ISSUE", "CRITICAL", "REJECTED"),
            finding("URGENT-CANDIDATE", "CRITICAL", "UNREVIEWED"),
        ],
        reviews: vec![Review {
            id: "review".into(),
            finding_id: "VALIDATED-ISSUE".into(),
            actor: "MODEL".into(),
            model_call_id: "call".into(),
            created_at: "2026-09-12T00:20:00.000Z".into(),
            revision: 1,
            draft: ReviewDraft {
                verdict: "VALIDATED".into(),
                rationale: "REVIEW-RATIONALE".into(),
                counter_evidence: "COUNTER-EVIDENCE".into(),
                missing_information: "MISSING-INFORMATION".into(),
                evidence: vec![],
                assessments: ["INPUT_CONTROL", "REACHABILITY", "DEFENSE_GAP"]
                    .iter()
                    .map(|check| ReviewAssessment {
                        check: (*check).into(),
                        status: "SUPPORTED".into(),
                        rationale: format!("{check}-RATIONALE"),
                        evidence: vec![EvidenceInput {
                            unit_id: "unit-1".into(),
                            start_line: 20,
                            end_line: 21,
                            quote: String::new(),
                        }],
                    })
                    .collect(),
            },
            evidence: vec![EvidenceRef {
                start_line: 20,
                end_line: 21,
                quote: "canonical_review_evidence();\n    next_line();".into(),
                ..reference("")
            }],
        }],
        tasks: vec![
            AgentTask {
                id: "planner".into(),
                role: "PLANNER".into(),
                status: "SUCCEEDED".into(),
                finished_at: "2026-09-12T00:01:00.000Z".into(),
                result: json!({"approach":"PLAN-APPROACH","priorities":[{"unit_id":"unit-1","reason":"PRIORITY-REASON"}],"limitations":["PLAN-LIMITATION"]}),
                ..Default::default()
            },
            AgentTask {
                id: "auditor".into(),
                role: "AUDITOR".into(),
                item_key: "unit-1".into(),
                status: "SUCCEEDED".into(),
                finished_at: "2026-09-12T00:10:00.000Z".into(),
                result: json!({"audited_unit_ids":["unit-1"],"limitations":["UNREAD-RANGE"]}),
                ..Default::default()
            },
            AgentTask {
                id: "reporter".into(),
                role: "REPORTER".into(),
                status: "SUCCEEDED".into(),
                finished_at: "2026-09-12T01:00:00.000Z".into(),
                result: json!({"summary":"NARRATIVE-SUMMARY\n第二段摘要","recommendations":["NARRATIVE-RECOMMENDATION"],"limitations":["REPORTER-LIMITATION"]}),
                ..Default::default()
            },
        ],
        annotations: vec![LogicAnnotation {
            id: "annotation".into(),
            run_id: "run".into(),
            revision: 1,
            actor: "HUMAN".into(),
            model_call_id: String::new(),
            updated_at: "2026-09-12T00:30:00.000Z".into(),
            draft: AnnotationDraft {
                unit_id: "unit-1".into(),
                tag: "AUTHENTICATION".into(),
                subtype: "PASSWORD".into(),
                rationale: "ANNOTATION-RATIONALE".into(),
                evidence: vec![],
            },
            evidence: vec![reference("password == expected")],
        }],
        ..Default::default()
    };
    Fixture {
        project: Project {
            id: "project".into(),
            name: "报告质量回归".into(),
            created_at: String::new(),
        },
        snapshot: Snapshot {
            id: "snapshot".into(),
            project_id: "project".into(),
            name: "parser.c".into(),
            kind: "SOURCE".into(),
            state: "READY".into(),
            target_sha256: "a".repeat(64),
            original_artifact_id: "source".into(),
            ..Default::default()
        },
        run: AuditRun {
            id: "run".into(),
            project_id: "project".into(),
            snapshot_id: "snapshot".into(),
            state: RunState::Partial,
            scope: "SECURITY_AUDIT".into(),
            created_at: String::new(),
            started_at: String::new(),
            finished_at: "2026-09-12T02:00:00.000Z".into(),
            unit_count: 2,
            summary: json!({
                "vulnerability_audit":"PARTIAL","independent_review":"PARTIAL","exploitation":"NOT_RUN",
                "audited_unit_count":2,"eligible_unit_count":2,"audit_coverage_gap":"COVERAGE-GAP",
                "files":[{"path":"future.ts","status":"UNSUPPORTED","reason":"UNSUPPORTED-FILE"}],
                "exclusions":[{"path":".git/config","reason":"EXCLUDED-FILE"}],
                "recovery":{"status":"PLAN_COMPLETED","conclusion":{"summary":"RECOVERY-CONCLUSION","limitations":["RECOVERY-LIMITATION"]},
                    "history":[{"tool":"upx","status":"PROCESSED","input_sha256":"INPUT-HASH","output_sha256":"OUTPUT-HASH",
                        "readable_artifact_id":"readable","result_artifact_id":"recovery-result","warnings":["RECOVERY-WARNING"]}]}
            }),
            error: "INTERRUPTION-REASON".into(),
        },
        units: vec![ProgramUnit {
            id: "unit-1".into(),
            run_id: "run".into(),
            snapshot_id: "snapshot".into(),
            artifact_id: "source".into(),
            unit: UnitInput {
                name: "parse_request".into(),
                path: "src/parse.c".into(),
                language: "c".into(),
                start_line: 10,
                end_line: 40,
                quality: "PARSED".into(),
                ..Default::default()
            },
        }],
        artifacts: vec![
            Artifact {
                id: "source".into(),
                name: "parser.c".into(),
                sha256: "a".repeat(64),
                size: 100,
                media_type: "text/plain".into(),
            },
            Artifact {
                id: "model-output".into(),
                name: "raw-model-output.json".into(),
                sha256: "b".repeat(64),
                size: 40000,
                media_type: "application/json".into(),
            },
            Artifact {
                id: "readable".into(),
                name: "readable.c".into(),
                sha256: "c".repeat(64),
                size: 100,
                media_type: "text/plain".into(),
            },
        ],
        audit,
    }
}
impl Fixture {
    fn render(&self, format: &str) -> String {
        let (bytes, _, _) = report::render_at(
            &self.project,
            &self.snapshot,
            &self.run,
            &self.units,
            &self.artifacts,
            &self.audit,
            format,
            SNAPSHOT_AT,
        )
        .unwrap();
        String::from_utf8(bytes).unwrap()
    }
    fn json(&self) -> Value {
        serde_json::from_str(&self.render("json")).unwrap()
    }
}

#[test]
fn human_formats_share_findings_review_evidence_coverage_and_saved_narrative() {
    let fixture = fixture();
    for format in ["html", "markdown"] {
        let text = fixture.render(format);
        for marker in [
            "SEVERITY",
            "REVIEW",
            "COUNTER",
            "INFORMATION",
            "RATIONALE",
            "canonical_review_evidence",
            "NARRATIVE",
            "UNREAD",
            "COVERAGE",
            "INTERRUPTION",
            "UNSUPPORTED",
            "EXCLUDED",
            "RECOVERY",
            "INPUT",
            "OUTPUT",
            "readable",
            "PASSWORD",
            "parse_request",
            "src/parse.c",
        ] {
            assert!(text.contains(marker), "{format} omitted {marker}");
        }
        assert!(
            text.contains("已完成 1/2"),
            "deduplicate successful units; do not trust stale summary count"
        );
        assert!(text.contains("PARTIAL"));
        assert!(!text.contains("状态：Partial"));
        assert!(text.find("URGENT").unwrap() < text.find("VALIDATED").unwrap());
        assert!(text.find("发现与复核").unwrap() < text.find("附录 A").unwrap());
        assert!(
            !text.contains("raw-model-output.json"),
            "keep internal dumps out of the human appendix"
        );
        assert_eq!(
            text.matches("canonical_review_evidence();").count(),
            1,
            "assessment citations share canonical evidence"
        );
    }
    let html = fixture.render("html");
    let html_headings: Vec<_> = html
        .split("<h2>")
        .skip(1)
        .map(|s| s.split("</h2>").next().unwrap())
        .collect();
    let markdown = fixture.render("markdown");
    let md_headings: Vec<_> = markdown
        .lines()
        .filter_map(|s| s.strip_prefix("## "))
        .collect();
    assert_eq!(html_headings, md_headings);
    let start = html.find("id=\"finding-2\"").unwrap();
    let end = html[start..].find("id=\"coverage\"").unwrap() + start;
    assert!(html[start..end].contains("静态结论范围"));
    assert!(html.find("<h2>已否决候选").unwrap() > html.find("<h2>发现与复核").unwrap());
}

#[test]
fn markdown_preserves_multiline_code_and_uses_a_fence_that_cannot_be_closed_by_evidence() {
    let mut fixture = fixture();
    let quoted = format!(
        "{}\n{}\n<script>alert('x')</script>\n{}\n",
        CODE,
        "\u{60}".repeat(5),
        "\u{60}".repeat(3)
    );
    fixture.audit.findings[0].evidence[0].quote = quoted.clone();
    let text = fixture.render("markdown");
    let fence = "\u{60}".repeat(6);
    assert!(text.contains(&format!("{fence}c\n{quoted}{fence}\n")));
    assert!(text.contains("第一段输入  \n第二段输入"));
    assert!(text.contains("reject(\"<unsafe> | value\");"));
    assert!(!text.contains("reject(&quot;"));
}

#[test]
fn html_escapes_all_untrusted_content_including_summary_and_quotes() {
    let mut fixture = fixture();
    fixture.snapshot.name = "</title><script>alert(1)</script>".into();
    fixture.project.name = "<img src=x onerror=alert(2)>".into();
    fixture.audit.tasks[2].result["summary"] = json!("<svg onload=alert(3)>summary</svg>");
    fixture.audit.findings[0].draft.recommendation =
        "<a href='https://evil.invalid'>click</a>".into();
    let html = fixture.render("html");
    for tag in ["<script", "<img", "<svg", "href='https://evil.invalid'"] {
        assert!(!html.contains(tag));
    }
    assert!(html.contains("&lt;unsafe&gt;"));
    assert!(html.contains("&lt;svg"));
    assert!(html.contains("form-action 'none'"));
}

#[test]
fn json_keeps_the_version_one_contract_and_complete_evidence() {
    let fixture = fixture();
    let doc = fixture.json();
    assert_eq!(doc["schema_version"], 1);
    assert_eq!(doc["generated_at"], SNAPSHOT_AT);
    assert_eq!(doc["run"]["state"], "PARTIAL");
    assert_eq!(doc["coverage"], doc["run"]["summary"]);
    assert_eq!(doc["checks"]["exploitation"], "NOT_RUN");
    assert_eq!(doc["audit"]["findings"][0]["evidence"][0]["quote"], CODE);
    assert_eq!(
        doc["audit"]["reviews"][0]["draft"]["assessments"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(doc["artifacts"].as_array().unwrap().len(), 3);
}

#[test]
fn later_human_review_does_not_reuse_outdated_model_summary() {
    let mut fixture = fixture();
    fixture.audit.findings[0].review_status = "REJECTED".into();
    let mut human = fixture.audit.reviews[0].clone();
    human.actor = "HUMAN".into();
    human.created_at = "2026-09-12T02:30:00.000Z".into();
    human.revision = 2;
    human.draft.verdict = "REJECTED".into();
    human.draft.rationale = "HUMAN-COUNTER-EVIDENCE".into();
    fixture.audit.reviews.push(human);
    for format in ["html", "markdown"] {
        let text = fixture.render(format);
        assert!(!text.contains("NARRATIVE"));
        assert!(text.contains("HUMAN"));
        assert!(text.contains("当前"));
    }
    assert!(
        fixture.render("json").contains("NARRATIVE-SUMMARY"),
        "keep historical evidence available"
    );
}

fn runtime(status: &str, has_result: bool) -> RuntimeRecord {
    RuntimeRecord {
        id: "runtime".into(),
        run_id: "verification-run".into(),
        source_run_id: "run".into(),
        finding_id: "VALIDATED-ISSUE".into(),
        status: status.into(),
        created_at: "2026-09-12T02:00:00.000Z".into(),
        config: RuntimeConfig {
            path: "src/parse.c".into(),
            ..Default::default()
        },
        result: has_result.then(|| RuntimeResult {
            target_sha256: "a".repeat(64),
            config_hash: "config-hash".into(),
            image_id: "local-environment".into(),
            target_scope: "COMPONENT".into(),
            recipe_artifact_id: "recipe".into(),
            observation_artifact_id: "observation".into(),
            observation: RuntimeObservation {
                schema_version: 1,
                mode: "VERIFY".into(),
                path: "src/parse.c".into(),
                ..Default::default()
            },
            tools: vec![],
        }),
    }
}
#[test]
fn pending_runtime_makes_a_terminal_run_report_interim() {
    let mut fixture = fixture();
    fixture.run.state = RunState::Completed;
    fixture.audit.runtime.push(runtime("QUEUED", false));
    let doc = fixture.json();
    assert_eq!(doc["interim"], true);
    assert_eq!(doc["checks"]["runtime_verification"], "RUNNING");
    assert!(fixture.render("html").contains("阶段报告"));
}
#[test]
fn a_cancelled_or_unknown_runtime_record_cannot_make_a_mixed_batch_complete() {
    let mut fixture = fixture();
    fixture.audit.runtime = vec![runtime("REPRODUCED", true), runtime("CANCELLED", true)];
    assert_eq!(fixture.json()["checks"]["runtime_verification"], "PARTIAL");
    fixture.audit.runtime[1].status = "UNKNOWN_RESULT".into();
    assert_eq!(fixture.json()["checks"]["runtime_verification"], "PARTIAL");
    fixture.audit.runtime[1].status = "NOT_REPRODUCED".into();
    assert_eq!(
        fixture.json()["checks"]["runtime_verification"],
        "COMPLETED"
    );
    fixture.audit.runtime = vec![runtime("CANCELLED", true)];
    assert_eq!(
        fixture.json()["checks"]["runtime_verification"],
        "CANCELLED"
    );
}
#[test]
fn runtime_uses_saved_scope_and_labels_log_excerpts_without_changing_json() {
    let mut fixture = fixture();
    let mut record = runtime("REPRODUCED", true);
    let stdout = "long output\n".repeat(100);
    record
        .result
        .as_mut()
        .unwrap()
        .observation
        .trials
        .push(RuntimeTrial {
            label: "baseline".into(),
            stdout: stdout.clone(),
            observed: false,
            processes_reaped: true,
            exit_code: Some(0),
            ..Default::default()
        });
    fixture.audit.runtime.push(record);
    for format in ["html", "markdown"] {
        let text = fixture.render(format);
        assert!(text.contains("COMPONENT"));
        assert!(text.contains("仅展示前 60 行"));
        assert!(text.contains("observation"));
        assert!(!text.contains("NARRATIVE"));
    }
    assert_eq!(
        fixture.json()["audit"]["runtime"][0]["result"]["observation"]["trials"][0]["stdout"],
        stdout
    );
}
#[test]
fn no_findings_and_no_audit_are_explicit_and_do_not_imply_safety() {
    let mut fixture = fixture();
    fixture.audit = AuditEvidence::default();
    fixture.run.state = RunState::Completed;
    fixture.run.summary = json!({});
    fixture.run.error.clear();
    for format in ["html", "markdown"] {
        let text = fixture.render(format);
        assert!(text.contains("尚未执行漏洞审计"));
        assert!(text.contains("未记录可核对的语义审计覆盖数量"));
        assert!(!text.contains("F-001"));
    }
}
#[test]
fn all_formats_keep_the_same_bounded_exploitation_claim() {
    let mut fixture = fixture();
    fixture.run.summary["exploitation"] = json!("COMPLETED");
    fixture.run.summary["exploitation_artifact_id"] = json!("exploit-evidence");
    fixture.run.summary["exploitation_input_artifact_id"] = json!("exploit-recipe");
    for format in ["html", "markdown"] {
        let text = fixture.render(format);
        assert!(text.contains("不据此推定任意代码执行"));
        assert!(!text.contains("稳定触发观察到的内存安全异常"));
    }
}

#[test]
fn repeated_trial_details_are_shared_but_each_observation_remains_visible() {
    let mut fixture = fixture();
    let mut record = runtime("REPRODUCED", true);
    let probe = RuntimeTrial {
        label: "probe".into(),
        input_json: "{\"stdin\":\"probe\"}".into(),
        input_sha256: "same-input".into(),
        stdout: "PROBE_OUTPUT".into(),
        observed: true,
        processes_reaped: true,
        exit_code: Some(0),
        ..Default::default()
    };
    record.result.as_mut().unwrap().observation.trials = vec![
        RuntimeTrial {
            label: "baseline".into(),
            input_json: "{\"stdin\":\"baseline\"}".into(),
            ..Default::default()
        },
        probe.clone(),
        RuntimeTrial {
            exit_code: Some(17),
            observed: false,
            ..probe
        },
    ];
    fixture.audit.runtime.push(record);
    let html = fixture.render("html");
    let markdown = fixture.render("markdown");
    for text in [&html, &markdown] {
        assert_eq!(text.matches("PROBE_OUTPUT").count(), 1);
        assert!(text.contains("第 3 轮的输入、异常和输出与第 2 轮相同"));
    }
    assert!(html.contains("<td>17</td>"));
    assert!(markdown.contains("| 17 |"));
    assert_eq!(
        fixture.json()["audit"]["runtime"][0]["result"]["observation"]["trials"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn evidence_captions_stay_attached_to_their_code_for_printing() {
    let fixture = fixture();
    let html = fixture.render("html");
    let caption = "<figure class=\"code-evidence\"><figcaption>src/parse.c · L12-L15 · 0x401000 · 产物 source</figcaption><pre>";
    assert!(html.contains(caption));
    assert!(html.contains(".code-evidence{break-inside:avoid}"));
}

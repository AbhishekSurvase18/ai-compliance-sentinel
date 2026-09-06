"""Compliance Sentinel console and command-line validation runner."""

import json

from agents import run_case, validate_scenarios
from auth import authenticate
from report import (
    generate_stakeholder_report,
    render_markdown,
    summary,
    verify_audit_chain,
    write_report,
)
from review import latest_review, record_review
from rules import SCENARIOS
from storage import ComplianceStore
from ingestion import load_json_events
from regulatory import OFFICIAL_FEEDS, assess_change, serialize_change


# ============================================================
# COMMAND LINE VALIDATION
# ============================================================

def run_validation() -> dict:
    reports = validate_scenarios(SCENARIOS)

    for item in reports:
        write_report(item)

    result = summary(reports)

    if result["validation_failed"]:
        failed = ", ".join(
            item["case_id"]
            for item in reports
            if item["validation"] == "fail"
        )
        raise RuntimeError(
            f"Scenario validation failed: {failed}"
        )

    return result


# ============================================================
# STREAMLIT APPLICATION
# ============================================================

def streamlit_app() -> None:
    import streamlit as st

    st.set_page_config(
        page_title="Compliance Sentinel",
        page_icon="🛡️",
        layout="wide",
    )

    @st.cache_data(ttl=300, show_spinner="Validating built-in scenarios...")
    def load_builtin_reports() -> list[dict]:
        return validate_scenarios(SCENARIOS)

    # --------------------------------------------------------
    # SESSION STATE
    # --------------------------------------------------------

    if "reviewer" not in st.session_state:
        st.session_state.reviewer = None

    if "uploaded_reports" not in st.session_state:
        st.session_state.uploaded_reports = None

    # --------------------------------------------------------
    # SIDEBAR - REVIEWER ACCESS
    # --------------------------------------------------------

    with st.sidebar:

        st.subheader("Reviewer Access")

        if st.session_state.reviewer:

            st.success(
                f"Signed in: "
                f"{st.session_state.reviewer.reviewer_id}"
            )

            st.caption(
                f"Role: {st.session_state.reviewer.role}"
            )

            if st.button(
                "Sign out",
                width="stretch",
            ):
                st.session_state.reviewer = None
                st.rerun()

        else:

            login_id = st.text_input(
                "Reviewer ID"
            )

            login_password = st.text_input(
                "Password",
                type="password",
            )

            if st.button(
                "Sign in",
                type="primary",
                width="stretch",
            ):

                reviewer = authenticate(
                    login_id,
                    login_password,
                )

                if reviewer:

                    st.session_state.reviewer = reviewer
                    st.rerun()

                else:

                    st.error(
                        "Invalid reviewer credentials"
                    )

    # --------------------------------------------------------
    # HEADER
    # --------------------------------------------------------

    st.title("🛡️ Compliance Sentinel")

    st.caption(
        "Four-agent regulatory surveillance for "
        "trading, lending, and communications"
    )

    st.info(
        "Built-in validation scope: 20 representative scenarios, "
        "versioned rules, human escalation, and append-only audit evidence."
    )

    # --------------------------------------------------------
    # INGEST EXTERNAL EVENTS
    # --------------------------------------------------------

    with st.expander(
        "📥 Ingest External Events"
    ):

        upload = st.file_uploader(
            "Upload JSON event or event array",
            type=["json"],
        )

        if upload:

            try:

                content = upload.getvalue().decode(
                    "utf-8"
                )

                result = load_json_events(
                    content
                )

                if result.errors:

                    st.error(
                        "Input quarantined: "
                        + " | ".join(
                            result.errors
                        )
                    )

                else:

                    st.success(
                        f"Validated "
                        f"{len(result.scenarios)} event(s)."
                    )

                    if st.button(
                        "▶ Analyze Uploaded Events"
                    ):

                        st.session_state.uploaded_reports = [
                            run_case(item)
                            for item in result.scenarios
                        ]

                        st.rerun()

            except Exception as error:

                st.error(
                    f"Unable to process uploaded file: {error}"
                )

    # --------------------------------------------------------
    # REGULATORY CHANGE ASSESSMENT
    # --------------------------------------------------------

    with st.expander(
        "⚖️ Assess Regulatory Change"
    ):

        with st.form(
            "regulatory-change-form"
        ):

            change_id = st.text_input(
                "Change ID"
            )

            source = st.selectbox(
                "Official Source",
                list(OFFICIAL_FEEDS),
            )

            title = st.text_input(
                "Change Title"
            )

            effective_date = st.text_input(
                "Effective Date (YYYY-MM-DD)"
            )

            jurisdictions = st.text_input(
                "Jurisdictions (comma separated)",
                value="US",
            )

            domains = st.multiselect(
                "Affected Domains",
                [
                    "trading",
                    "lending",
                    "communications",
                ],
                default=["trading"],
            )

            submitted = st.form_submit_button(
                "Assess Impact",
                type="primary",
            )

        if submitted:

            try:

                assessment = assess_change(
                    {
                        "change_id": change_id,
                        "source": source,
                        "title": title,
                        "effective_date": (
                            effective_date
                            if effective_date
                            else None
                        ),
                        "jurisdictions": [
                            item.strip()
                            for item in jurisdictions.split(",")
                            if item.strip()
                        ],
                        "domains": domains,
                    }
                )

            except ValueError as error:

                st.error(
                    str(error)
                )

            except Exception as error:

                st.error(
                    f"Assessment failed: {error}"
                )

            else:

                st.success(
                    f"Preliminary impact: "
                    f"{assessment.impact}. "
                    f"Human validation required."
                )

                st.json(
                    serialize_change(
                        assessment
                    )
                )

    # --------------------------------------------------------
    # LOAD REPORTS
    # --------------------------------------------------------

    try:

        reports = (
            st.session_state.uploaded_reports
            or load_builtin_reports()
        )

    except Exception as error:

        st.error(
            f"Unable to load compliance scenarios: {error}"
        )

        return

    if not reports:

        st.warning(
            "No compliance scenarios available."
        )

        return

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    try:

        totals = summary(reports)

    except Exception as error:

        st.error(
            f"Unable to calculate summary: {error}"
        )

        return

    # --------------------------------------------------------
    # AUDIT CHAIN
    # --------------------------------------------------------

    try:

        chain_ok, chain_message = (
            verify_audit_chain()
        )

    except Exception as error:

        chain_ok = False
        chain_message = str(error)

    # --------------------------------------------------------
    # STORAGE COUNTS
    # --------------------------------------------------------

    try:

        store_counts = (
            ComplianceStore().counts()
        )

    except Exception:

        store_counts = {}

    # --------------------------------------------------------
    # DASHBOARD METRICS
    # --------------------------------------------------------

    st.subheader(
        "📊 Compliance Overview"
    )

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "Scenarios Validated",
            totals.get("cases", 0),
        )

    with col2:

        st.metric(
            "Expected Outcomes",
            (
                f"{totals.get('validation_passed', 0)}"
                f"/"
                f"{totals.get('cases', 0)}"
            ),
        )

    with col3:

        st.metric(
            "Human Escalations",
            totals.get("escalations", 0),
        )

    col4, col5, col6 = st.columns(3)

    with col4:

        st.metric(
            "Critical / High",
            (
                f"{totals.get('critical', 0)}"
                f" / "
                f"{totals.get('high', 0)}"
            ),
        )

    with col5:

        stored_cases = store_counts.get(
            "reports",
            0,
        )

        st.metric(
            "Unique Stored Cases",
            stored_cases,
        )

    with col6:

        st.metric(
            "Processing Runs",
            store_counts.get(
                "runs",
                stored_cases,
            ),
        )

    # --------------------------------------------------------
    # AUDIT STATUS
    # --------------------------------------------------------

    if chain_ok:

        st.success(
            "✅ Audit chain verified"
        )

    else:

        st.error(
            f"⚠️ Audit chain: {chain_message}"
        )

    # ========================================================
    # LATENCY
    # ========================================================

    with st.container(border=True):

        st.subheader(
            "⏱️ Latency Percentiles"
        )

        latency_data = (
            totals.get(
                "latency_percentiles_ms",
                {},
            )
        )

        if latency_data:

            for agent, values in latency_data.items():

                agent_name = agent.replace(
                    "_",
                    " ",
                ).title()

                p50 = values.get(
                    "p50",
                    0,
                )

                p95 = values.get(
                    "p95",
                    0,
                )

                p99 = values.get(
                    "p99",
                    0,
                )

                st.markdown(
                    f"**{agent_name}**  \n"
                    f"P50: `{p50} ms`  |  "
                    f"P95: `{p95} ms`  |  "
                    f"P99: `{p99} ms`"
                )

                st.divider()

        else:

            st.info(
                "No latency data available."
            )

    # ========================================================
    # CASE QUEUE
    # ========================================================

    st.subheader(
        "📋 Case Queue"
    )

    # --------------------------------------------------------
    # SEARCH HISTORICAL REPORTS
    # --------------------------------------------------------

    with st.expander(
        "🔎 Search Historical Reports"
    ):

        search_query = st.text_input(
            "Case ID, Trace ID, or Risk"
        )

        if search_query.strip():

            try:

                search_results = (
                    ComplianceStore()
                    .search_reports(
                        search_query
                    )
                )

                if search_results:

                    st.write(
                        f"Found "
                        f"{len(search_results)} "
                        f"result(s)"
                    )

                    for index, result in enumerate(
                        search_results,
                        start=1,
                    ):

                        with st.expander(
                            f"Result {index}"
                        ):

                            if isinstance(
                                result,
                                dict,
                            ):

                                for key, value in result.items():

                                    st.write(
                                        f"**{key}:** {value}"
                                    )

                            else:

                                st.write(
                                    result
                                )

                else:

                    st.info(
                        "No historical reports found."
                    )

            except Exception as error:

                st.error(
                    f"Search failed: {error}"
                )

    # ========================================================
    # SELECT CASE
    # ========================================================

    case_ids = [
        item.get(
            "case_id",
            f"case-{index}",
        )
        for index, item in enumerate(
            reports,
            start=1,
        )
    ]

    selected = st.selectbox(
        "Select a Case",
        case_ids,
    )

    report = next(
        (
            item
            for item in reports
            if item.get("case_id") == selected
        ),
        None,
    )

    if report is None:

        st.error(
            "Selected case could not be found."
        )

        return

    review = None
    if selected:
        try:

            review = latest_review(selected)

        except Exception:

            review = None

    # ========================================================
    # SYSTEM HEALTH
    # ========================================================

    with st.container(border=True):

        st.subheader(
            "💚 System Health"
        )

        audit = report.get(
            "audit",
            {},
        )

        latencies = audit.get(
            "latency_ms",
            {},
        )

        statuses = audit.get(
            "agent_status",
            {},
        )

        health_columns = st.columns(4)

        agent_names = (
            "transaction_monitor",
            "communication_scanner",
            "regulatory_update_tracker",
            "report_generator",
        )

        for column, agent_name in zip(
            health_columns,
            agent_names,
        ):

            with column:

                latency = latencies.get(
                    agent_name,
                    0,
                )

                status = statuses.get(
                    agent_name,
                    "completed",
                )

                st.metric(
                    agent_name.replace(
                        "_",
                        " ",
                    ).title(),
                    str(status),
                    f"{latency} ms",
                )

        st.caption(
            f"Pipeline latency: "
            f"{latencies.get('pipeline', 0)} ms | "
            f"Messages: "
            f"{audit.get('message_count', 0)}"
        )

    # ========================================================
    # CASE DETAILS
    # ========================================================

    left, right = st.columns(2)

    # --------------------------------------------------------
    # LEFT COLUMN
    # --------------------------------------------------------

    with left:

        risk = report.get(
            "risk",
            "unknown",
        )

        validation = report.get(
            "validation",
            "unknown",
        )

        expected_risk = report.get(
            "expected_risk",
            "unknown",
        )

        recommended_action = report.get(
            "recommended_action",
            "No action specified",
        )

        st.subheader(
            "🎯 Case Assessment"
        )

        st.write(
            f"**Risk:** {str(risk).upper()}"
        )

        st.write(
            f"**Validation:** "
            f"{str(validation).upper()} "
            f"(expected {expected_risk})"
        )

        st.write(
            f"**Action:** "
            f"{recommended_action}"
        )

        st.subheader(
            "🔍 Findings"
        )

        findings = report.get(
            "findings",
            [],
        )

        if findings:

            for index, finding in enumerate(
                findings,
                start=1,
            ):

                finding_id = finding.get(
                    "finding_id",
                    f"Finding {index}",
                )

                severity = finding.get(
                    "severity",
                    "unknown",
                )

                status = finding.get(
                    "status",
                    "unknown",
                )

                with st.expander(
                    f"{finding_id} — "
                    f"{str(severity).upper()}"
                ):

                    st.write(
                        f"**Rule ID:** "
                        f"{finding.get('rule_id', 'N/A')}"
                    )

                    st.write(
                        f"**Severity:** "
                        f"{severity}"
                    )

                    st.write(
                        f"**Confidence:** "
                        f"{finding.get('confidence', 'N/A')}"
                    )

                    st.write(
                        f"**Status:** "
                        f"{status}"
                    )

        else:

            st.info(
                "No findings available."
            )

    # --------------------------------------------------------
    # RIGHT COLUMN
    # --------------------------------------------------------

    with right:

        # ----------------------------------------------------
        # AUDIT TRAIL
        # ----------------------------------------------------

        with st.container(border=True):

            st.subheader(
                "🧾 Audit Trail"
            )

            st.json(
                audit
            )

            try:

                markdown_report = (
                    render_markdown(
                        report
                    )
                )

                st.download_button(
                    "⬇️ Download Markdown Report",
                    markdown_report,
                    file_name=(
                        f"{selected}-report.md"
                    ),
                    mime="text/markdown",
                )

            except Exception as error:

                st.warning(
                    f"Report generation unavailable: {error}"
                )

        # ----------------------------------------------------
        # STAKEHOLDER VIEW
        # ----------------------------------------------------

        with st.container(border=True):

            st.subheader(
                "👥 Stakeholder View"
            )

            profile = st.selectbox(
                "Report Profile",
                [
                    "compliance_committee",
                    "senior_management",
                    "external_auditor",
                    "regulator",
                ],
            )

            try:

                stakeholder_report = (
                    generate_stakeholder_report(
                        report,
                        profile,
                    )
                )

                st.json(
                    stakeholder_report
                )

            except Exception as error:

                st.error(
                    f"Unable to generate stakeholder report: {error}"
                )

        # ----------------------------------------------------
        # HUMAN REVIEW
        # ----------------------------------------------------

        with st.container(border=True):

            st.subheader(
                "👤 Human Review"
            )

            if review:

                st.write(
                    f"**Decision:** "
                    f"{str(review.get('decision', '')).upper()}"
                )

                st.caption(
                    f"{review.get('reviewer_id', 'Unknown')} · "
                    f"{review.get('reviewer_role', 'Unknown')} · "
                    f"{review.get('created_at', 'Unknown')}"
                )

                st.write(
                    review.get(
                        "rationale",
                        "No rationale provided.",
                    )
                )

            else:

                st.caption(
                    "No reviewer decision recorded "
                    "for this case."
                )

            if st.session_state.reviewer:

                with st.form(
                    "review-form"
                ):

                    decision = st.selectbox(
                        "Decision",
                        [
                            "approve",
                            "reject",
                            "escalate",
                        ],
                    )

                    rationale = st.text_area(
                        "Decision Rationale"
                    )

                    submitted = (
                        st.form_submit_button(
                            "Record Decision",
                            type="primary",
                        )
                    )

                if submitted:

                    try:

                        record_review(
                            report,
                            st.session_state.reviewer.reviewer_id,
                            st.session_state.reviewer.role,
                            decision,
                            rationale,
                        )

                    except ValueError as error:

                        st.error(
                            str(error)
                        )

                    except Exception as error:

                        st.error(
                            f"Unable to record review: {error}"
                        )

                    else:

                        st.success(
                            "Decision recorded in the "
                            "append-only review log."
                        )

                        st.rerun()

            else:

                st.info(
                    "Sign in from the sidebar to "
                    "record a human decision."
                )

    # ========================================================
    # WRITE REPORTS
    # ========================================================

    st.divider()

    if st.button(
        "💾 Write All Audit Reports",
        type="primary",
    ):

        try:

            for item in reports:
                write_report(item)

            st.success(
                "Audit reports written to reports/"
            )

        except Exception as error:

            st.error(
                f"Unable to write reports: {error}"
            )


# ============================================================
# APPLICATION ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        from streamlit.runtime.scriptrunner import (
            get_script_run_ctx,
        )

    except ImportError:

        get_script_run_ctx = (
            lambda **kwargs: None
        )

    if (
        get_script_run_ctx(
            suppress_warning=True
        )
        is not None
    ):

        streamlit_app()

    else:

        print(
            json.dumps(
                run_validation(),
                indent=2,
            )
        )
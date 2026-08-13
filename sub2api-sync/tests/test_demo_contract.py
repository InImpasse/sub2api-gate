import gzip
import pathlib
import re
import unittest


DEMO = (pathlib.Path(__file__).resolve().parents[2] / "demo" / "index.html").read_text()


def contrast_ratio(foreground, background):
    values = sorted((relative_luminance(foreground), relative_luminance(background)), reverse=True)
    return (values[0] + 0.05) / (values[1] + 0.05)


def relative_luminance(color):
    channels = [int(color[index:index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [
        value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4
        for value in channels
    ]
    return (0.2126 * linear[0]) + (0.7152 * linear[1]) + (0.0722 * linear[2])


class DemoContractTests(unittest.TestCase):
    def test_static_demo_stays_within_the_resource_budget(self):
        encoded = DEMO.encode()
        self.assertLessEqual(len(encoded), 56 * 1024)
        self.assertLessEqual(len(gzip.compress(encoded, mtime=0)), 14 * 1024)

    def test_stylesheet_blocks_are_structurally_balanced(self):
        styles = re.findall(r"<style>(.*?)</style>", DEMO, re.DOTALL)
        self.assertTrue(styles)
        for stylesheet in styles:
            without_comments = re.sub(r"/\*.*?\*/", "", stylesheet, flags=re.DOTALL)
            without_strings = re.sub(
                r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*' ''',
                "",
                without_comments,
                flags=re.VERBOSE,
            )
            depth = 0
            for character in without_strings:
                if character == "{":
                    depth += 1
                elif character == "}":
                    depth -= 1
                    self.assertGreaterEqual(depth, 0, "unexpected closing CSS brace")
            self.assertEqual(depth, 0, "unclosed CSS rule")

    def test_interaction_renders_do_not_replay_entry_animation(self):
        self.assertIn("#app.no-entry-motion .fade-up", DEMO)
        self.assertIn("animation: none;", DEMO)
        self.assertIn("app.classList.toggle(\"no-entry-motion\", renderCount > 0)", DEMO)

    def test_typography_and_responsive_breakpoints_are_bounded(self):
        self.assertIn("font-size: 42px;", DEMO)
        self.assertIn(".hero-title, .workspace-copy h1, h1 { font-size: 32px; }", DEMO)
        self.assertIn("@media (max-width: 980px)", DEMO)
        self.assertIn("@media (max-width: 680px)", DEMO)
        self.assertNotRegex(DEMO, r"font-size:[^;]*\b(vw|vh|vmin|vmax)\b")
        self.assertNotRegex(DEMO, r"letter-spacing:\s*-")
        self.assertIn("--radius-xl: 20px;", DEMO)

    def test_mobile_layout_avoids_fixed_badge_and_action_overlaps(self):
        mobile = DEMO.split("@media (max-width: 680px)", 1)[1].split("</style>", 1)[0]
        self.assertIn(".demo-badge", mobile)
        self.assertIn("position: static;", mobile)
        self.assertIn(".workspace-actions", mobile)
        self.assertIn("grid-template-columns: 1fr;", mobile)

    def test_two_hundred_percent_zoom_has_an_extreme_narrow_reflow(self):
        narrow = DEMO.split("@media (max-width: 240px)", 1)[1].split("</style>", 1)[0]
        self.assertIn("width: calc(100% - 12px);", narrow)
        self.assertIn(".brand-row", narrow)
        self.assertIn("grid-template-columns: minmax(0, 1fr);", narrow)
        self.assertIn("white-space: normal;", narrow)

    def test_demo_uses_glass_panels_without_decorative_orbs(self):
        self.assertNotIn("gradient(", DEMO)
        self.assertNotIn("ambient-orb", DEMO)
        self.assertIn("backdrop-filter: blur(20px) saturate(180%)", DEMO)
        self.assertIn("--surface: rgba(28, 28, 30, 0.62);", DEMO)
        self.assertIn("button:focus-visible", DEMO)
        self.assertIn("prefers-reduced-motion", DEMO)
        self.assertIn('id="a-group"', DEMO)
        self.assertIn("openai-default", DEMO)
        self.assertIn("Test API key", DEMO)
        self.assertIn("203.0.113.0/24", DEMO)

    def test_demo_presents_uuid_as_legacy_migration_compatibility(self):
        self.assertIn("Access key or legacy UUID", DEMO)
        self.assertIn("accepted only during its migration window", DEMO)
        self.assertNotIn("Access key or UUID", DEMO)

    def test_demo_verification_lifecycle_has_accessible_status_and_retry(self):
        self.assertIn('id="turnstileStatus"', DEMO)
        self.assertIn('role="status" aria-live="polite"', DEMO)
        self.assertIn('id="turnstileRetry"', DEMO)
        self.assertIn("Verification complete.", DEMO)
        self.assertIn("Verification expired. Complete it again.", DEMO)
        self.assertIn('turnstileStatus.setAttribute("role", alert ? "alert" : "status")', DEMO)

    def test_demo_reports_form_and_clipboard_errors_without_window_alert(self):
        self.assertIn('id="allowFormStatus"', DEMO)
        self.assertIn('id="copyStatus"', DEMO)
        self.assertIn("Select the value and copy it manually.", DEMO)
        self.assertNotIn('alert("Invalid key.', DEMO)

    def test_faint_text_meets_aa_contrast_on_the_page_background(self):
        light_theme = DEMO.split("@media (prefers-color-scheme: dark)", 1)[0]
        faint = re.search(r"--text-faint:\s*(#[0-9a-f]{6})", light_theme, re.IGNORECASE).group(1)
        background = re.search(r"--bg:\s*(#[0-9a-f]{6})", light_theme, re.IGNORECASE).group(1)

        self.assertGreaterEqual(contrast_ratio(faint, background), 4.5)

    def test_admin_tabs_use_roving_focus_and_complete_aria_relationships(self):
        self.assertIn('id="tab-users-button"', DEMO)
        self.assertIn('aria-controls="tab-users"', DEMO)
        self.assertIn('tabindex="0"', DEMO)
        self.assertIn('id="tab-add-button"', DEMO)
        self.assertIn('aria-controls="tab-add"', DEMO)
        self.assertIn('tabindex="-1"', DEMO)
        self.assertIn('aria-labelledby="tab-users-button"', DEMO)
        self.assertIn('aria-labelledby="tab-add-button"', DEMO)
        self.assertIn('tab.setAttribute("tabindex", active ? "0" : "-1")', DEMO)
        for key in ("ArrowLeft", "ArrowRight", "Home", "End"):
            self.assertIn(f'"{key}"', DEMO)


if __name__ == "__main__":
    unittest.main()

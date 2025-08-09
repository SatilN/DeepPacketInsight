# reporting.py
from jinja2 import Template

class HTMLReporter:
    def generate(self, analysis_results):
        with open("templates/report.html") as f:
            template = Template(f.read())
        return template.render(
            top_talkers=analysis_results['top_talkers'],
            alerts=analysis_results['alerts']
        )
from mcp_scanner.checkers.base import Severity


class ScoreCalculator:
    def calculate(self, findings: list) -> tuple[int, str]:
        score = 100
        for f in findings:
            score -= f.severity.weight
        score = max(0, score)
        grade = self._score_to_grade(score)
        return score, grade

    def _score_to_grade(self, score: int) -> str:
        if score >= 90:
            return "A"
        if score >= 70:
            return "B"
        if score >= 50:
            return "C"
        if score >= 30:
            return "D"
        return "F"

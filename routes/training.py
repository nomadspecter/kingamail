"""
routes/training.py - Employee Cybersecurity Awareness & Interactive Quizzes
----------------------------------------------------------------------------
Student explanation:
Provides interactive training courses and multiple-choice quizzes:
1. Lists awareness modules covering social engineering, CEO fraud, and lookalike domains.
2. Loads questions and options dynamically from the quiz_question and quiz_option database tables.
3. Scores employee quiz submissions in real-time and records progress in the quiz_result table.
"""

from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, session
from database import db
from models import TrainingModule, QuizQuestion, QuizOption, QuizResult, User
from routes.auth import login_required

training_bp = Blueprint("training", __name__)


@training_bp.route("/")
@training_bp.route("/modules")
@login_required
def modules():
    """
    Displays the catalog of available cybersecurity awareness modules.
    Shows the current user's quiz completion score and pass/fail status for each course.
    """
    user_id = session.get("user_id")
    all_modules = TrainingModule.query.order_by(TrainingModule.id).all()

    # Map user's existing quiz results by module_id
    user_results = {
        qr.training_module_id: qr
        for qr in QuizResult.query.filter_by(user_id=user_id).all()
    }

    modules_with_progress = []
    for mod in all_modules:
        modules_with_progress.append({
            "module": mod,
            "result": user_results.get(mod.id),
            "question_count": len(mod.questions)
        })

    completed_count = sum(1 for item in modules_with_progress if item["result"] and item["result"].passed)

    return render_template(
        "training_modules.html",
        modules_data=modules_with_progress,
        completed_count=completed_count,
        total_modules=len(all_modules)
    )


@training_bp.route("/module/<int:module_id>")
@login_required
def view_module(module_id):
    """
    Displays the educational lesson content and interactive 5-question assessment.
    Questions and multiple-choice options are loaded dynamically from the database.
    """
    user_id = session.get("user_id")
    module = TrainingModule.query.get_or_404(module_id)
    questions = QuizQuestion.query.filter_by(module_id=module.id).order_by(QuizQuestion.id).all()
    past_result = QuizResult.query.filter_by(user_id=user_id, training_module_id=module.id).first()

    return render_template(
        "training_detail.html",
        module=module,
        questions=questions,
        past_result=past_result
    )


@training_bp.route("/quiz/<int:module_id>", methods=["POST"])
@login_required
def submit_quiz(module_id):
    """
    Evaluates employee quiz answers against the quiz_option database table.
    Calculates percentage score, establishes pass/fail threshold (70%),
    and records results in the quiz_result table.
    """
    user_id = session.get("user_id")
    module = TrainingModule.query.get_or_404(module_id)
    questions = QuizQuestion.query.filter_by(module_id=module.id).all()

    if not questions:
        flash("No questions found for this module.", "warning")
        return redirect(url_for("training.view_module", module_id=module.id))

    total_questions = len(questions)
    correct_count = 0
    detailed_results = []

    # Evaluate each question against selected option
    for q in questions:
        selected_opt_id = request.form.get(f"question_{q.id}")
        is_correct = False
        selected_text = "No option selected"

        if selected_opt_id and selected_opt_id.isdigit():
            opt = QuizOption.query.get(int(selected_opt_id))
            if opt and opt.question_id == q.id:
                selected_text = opt.option_text
                if opt.is_correct:
                    is_correct = True
                    correct_count += 1

        # Locate correct option text for educational feedback
        correct_opt = next((o.option_text for o in q.options if o.is_correct), "N/A")

        detailed_results.append({
            "question": q.question_text,
            "explanation": q.explanation,
            "selected": selected_text,
            "correct_answer": correct_opt,
            "is_correct": is_correct
        })

    # Calculate score percentage
    score_percentage = int((correct_count / total_questions) * 100) if total_questions > 0 else 0
    passed = score_percentage >= 70

    # Save / Update QuizResult record
    result_record = QuizResult.query.filter_by(
        user_id=user_id,
        training_module_id=module.id
    ).first()

    if not result_record:
        result_record = QuizResult(
            user_id=user_id,
            training_module_id=module.id,
            score=score_percentage,
            total_questions=total_questions,
            correct_answers=correct_count,
            passed=passed,
            completed_at=datetime.utcnow()
        )
        db.session.add(result_record)
    else:
        # Keep highest score or update
        if score_percentage >= result_record.score:
            result_record.score = score_percentage
            result_record.correct_answers = correct_count
            result_record.passed = passed
            result_record.completed_at = datetime.utcnow()

    db.session.commit()

    if passed:
        flash(f"🎉 Congratulations! You passed '{module.title}' with a score of {score_percentage}% ({correct_count}/{total_questions} correct).", "success")
    else:
        flash(f"Assessment score: {score_percentage}% ({correct_count}/{total_questions} correct). Passing threshold is 70%. Review the explanations below and try again.", "warning")

    return render_template(
        "quiz_result.html",
        module=module,
        score=score_percentage,
        correct_count=correct_count,
        total_questions=total_questions,
        passed=passed,
        details=detailed_results
    )

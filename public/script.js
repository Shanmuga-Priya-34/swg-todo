document.addEventListener("DOMContentLoaded", () => {
    const toggleForms = document.querySelectorAll(".toggle-task-form");
    const deleteForms = document.querySelectorAll(".delete-task-form");

    toggleForms.forEach(form => {
        form.addEventListener("submit", (e) => {
            if (!confirm("Mark task as complete/incomplete?")) {
                e.preventDefault();
            }
        });
    });

    deleteForms.forEach(form => {
        form.addEventListener("submit", (e) => {
            if (!confirm("Are you sure you want to delete this task?")) {
                e.preventDefault();
            }
        });
    });
});

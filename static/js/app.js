document.addEventListener("DOMContentLoaded", () => {
  const form = document.querySelector(".scan-form");
  if (form) {
    form.addEventListener("submit", () => {
      const button = form.querySelector("button");
      if (button) button.textContent = "Scanning...";
    });
  }

  document.querySelectorAll(".confirm-form").forEach((confirmForm) => {
    confirmForm.addEventListener("submit", (event) => {
      const prompt = confirmForm.action.includes("/clear")
        ? "Clear all scan history? This cannot be undone."
        : "Delete this scan record?";
      if (!window.confirm(prompt)) event.preventDefault();
    });
  });
});

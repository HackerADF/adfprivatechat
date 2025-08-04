// JavaScript to handle tab navigation
function showTab(tabName) {
  const tabs = document.querySelectorAll(".tab-content");
  const buttons = document.querySelectorAll(".tab-button");

  // Hide all tabs
  tabs.forEach((tab) => tab.classList.remove("active"));

  // Remove active class from all buttons
  buttons.forEach((button) => button.classList.remove("active"));

  // Show the clicked tab and add active class to the button
  document.getElementById(tabName).classList.add("active");
  document
    .querySelector(`[onclick="showTab('${tabName}')"]`)
    .classList.add("active");
}

// Default tab to display
document.addEventListener("DOMContentLoaded", () => {
  showTab("account");
});

// JavaScript to handle tab navigation


// Handle username change
document
  .getElementById("changeUsernameBtn")
  .addEventListener("click", async () => {
    const newUsername = document.getElementById("new-username").value.trim();
    const password = document.getElementById("username-password").value;
    const errorMessage = document.getElementById("error-message");
    const successMessage = document.getElementById("success-message");

    // Reset any existing error messages
    errorMessage.style.display = "none";
    successMessage.style.display = "none";

    // Check if the new username is too short
    if (newUsername.length < 3) {
      errorMessage.textContent = "New username must be at least 3 characters.";
      errorMessage.style.display = "block";
      return;
    }

    // Check username format (alphanumeric, underscores, periods only)
    const usernameLower = newUsername.toLowerCase();
    const usernameRegex = /^[a-z0-9_.]+$/i;
    if (!usernameRegex.test(usernameLower)) {
      errorMessage.textContent =
        "Username can only contain letters, numbers, underscores, and periods.";
      errorMessage.style.display = "block";
      return;
    }

    // Forbidden words list
    const forbiddenWords = [
      "owner", "mod", "admin", "staff", "helper", "adf", "nsh", "nicole107h", "tractors101",
      "fuck", "shit", "bitch", "ass", "nigger", "nigga", "founder", "faggot", "hoe",
      "shigga", "yn", "bich", "niga"
    ];

    // Check if the new username contains forbidden words
    for (let word of forbiddenWords) {
      if (usernameLower.includes(word)) {
        errorMessage.textContent = `Username cannot contain restricted words like "${word}".`;
        errorMessage.style.display = "block";
        return;
      }
    }

    // Send the change username request to the server
    try {
      const res = await fetch("/change-username", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `newUsername=${encodeURIComponent(newUsername)}&password=${encodeURIComponent(password)}`
      });
      const data = await res.json();

      if (data.success) {
        successMessage.textContent = "Username successfully changed!";
        successMessage.style.display = "block";
        return
      } else {
        errorMessage.textContent = data.message || "Failed to change username.";
        errorMessage.style.display = "block";
      }
    } catch (err) {
      errorMessage.textContent = "Error connecting to server.";
      errorMessage.style.display = "block";
    }
  });

// Handle password change
document
  .getElementById("changePasswordBtn")
  .addEventListener("click", async () => {
    const currentPassword = document.getElementById("currentPassword").value;
    const newPassword = document.getElementById("newPassword").value;
    const confirmNewPassword =
      document.getElementById("confirmNewPassword").value;
    const errorMessage = document.getElementById("error-message");

    errorMessage.style.display = "none";

    if (newPassword !== confirmNewPassword) {
      errorMessage.textContent = "New passwords do not match.";
      errorMessage.style.display = "block";
      return;
    }

    if (newPassword.length < 6) {
      errorMessage.textContent = "Password must be at least 6 characters.";
      errorMessage.style.display = "block";
      return;
    }

    try {
      const res = await fetch("/change-password", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `currentPassword=${encodeURIComponent(
          currentPassword
        )}&newPassword=${encodeURIComponent(newPassword)}`,
      });

      const data = await res.json();

      if (data.success) {
        alert("Password successfully changed!");
        location.reload();
      } else {
        errorMessage.textContent = data.message || "Failed to change password.";
        errorMessage.style.display = "block";
      }
    } catch (err) {
      errorMessage.textContent = "Error connecting to server.";
      errorMessage.style.display = "block";
    }
  });


// Handle password change
document
  .getElementById("changePasswordBtn")
  .addEventListener("click", async () => {
    const currentPassword = document.getElementById("currentPassword").value;
    const newPassword = document.getElementById("newPassword").value;
    const confirmNewPassword =
      document.getElementById("confirmNewPassword").value;
    const errorMessage = document.getElementById("error-message");

    errorMessage.style.display = "none";

    if (newPassword !== confirmNewPassword) {
      errorMessage.textContent = "New passwords do not match.";
      errorMessage.style.display = "block";
      return;
    }

    if (newPassword.length < 6) {
      errorMessage.textContent = "Password must be at least 6 characters.";
      errorMessage.style.display = "block";
      return;
    }

    try {
      const res = await fetch("/change-password", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `currentPassword=${encodeURIComponent(
          currentPassword
        )}&newPassword=${encodeURIComponent(newPassword)}`,
      });

      const data = await res.json();

      if (data.success) {
        alert("Password successfully changed!");
        location.reload();
      } else {
        errorMessage.textContent = data.message || "Failed to change password.";
        errorMessage.style.display = "block";
      }
    } catch (err) {
      errorMessage.textContent = "Error connecting to server.";
      errorMessage.style.display = "block";
    }
  });

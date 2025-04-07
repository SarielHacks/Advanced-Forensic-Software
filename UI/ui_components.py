class UIComponents:
    """Handles UI-related reusable components like displaying messages."""
    
    @staticmethod
    def show_message(message):
        """Displays a simple message."""
        print(f"UI Message: {message}")

    @staticmethod
    def show_error(error_message):
        """Displays an error message."""
        print(f"Error: {error_message}")

    @staticmethod
    def show_success(success_message):
        """Displays a success message."""
        print(f"Success: {success_message}")

class UIFeedback:
    """Handles user feedback-related UI elements."""
    
    @staticmethod
    def show_feedback(feedback):
        """Displays feedback messages."""
        print(f"Feedback: {feedback}")

    @staticmethod
    def ask_confirmation(question):
        """Simulates asking the user for confirmation (Yes/No)."""
        response = input(f"{question} (yes/no): ").strip().lower()
        return response == "yes"

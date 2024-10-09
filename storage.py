import os

class Storage:
    """
    Class for saving content to a file with extra functions for validation and folder creation.
    """

    def __init__(self, folder: str, filename: str, content: str):
        """
        Constructor for the Storage class.

        Args:
        folder (str): The folder where the file should be saved.
        filename (str): The filename for the file to be saved.
        content (str): The content to be saved in the file.
        """
        self.folder = folder
        self.filename = filename
        self.content = content

    @property
    def filepath(self) -> str:
        """
        Returns the full filepath (folder + filename) for the file to be saved.

        Returns:
        str: The full filepath.
        """
        return f"{self.folder}/{self.filename}"

    def validate(self) -> bool:
        """
        Validates if the folder and filename are valid.

        Returns:
        bool: True if the folder and filename are valid, False otherwise.
        """
        if not os.path.isdir(self.folder):
            return False
        if not self.filename:
            return False
        return True

    def create_folder(self) -> None:
        """
        Creates the folder if it doesn't exist.
        """
        if not os.path.isdir(self.folder):
            os.makedirs(self.folder)

    def save(self) -> None:
        """
        Saves the content to the file.
        """
        if self.validate():
            self.create_folder()
            with open(self.filepath, "w") as file:
                file.write(self.content)
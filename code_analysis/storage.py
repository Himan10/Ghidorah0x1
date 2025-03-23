import os
from django.conf import settings
from django.core.files.storage import FileSystemStorage

class UserDirectoryFileSystemStorage(FileSystemStorage):
    def get_available_name(self, name, max_length=None):
        """
        Return a filename that's free on the target storage system and
        available for new content to be written to.
        """
        dir_name = os.path.dirname(name)
        file_name = os.path.basename(name)
        new_name = os.path.join(dir_name, file_name)
        return new_name

    def _save(self, name, content):
        """
        Save the file to the storage system.
        """
        user_directory = self.location
        return super()._save(os.path.join(user_directory, name), content)

def user_directory_path(instance, filename):
    """
    Generate file path for the user.
    """
    return f'{instance.user.username}-secure_code_review/{filename}'

import base64
import os
import stat

from six.moves import input


def install_and_import(pkg):
    """
    Installs latest versions of required packages.
    :param pkg: Package name.
    """
    import importlib
    try:
        importlib.import_module(pkg)
    except ImportError:
        import pip
        pip.main(["install", pkg])
    finally:
        globals()[pkg] = importlib.import_module(pkg)


def analyze_aws(aws_storage_path):
    """
    Analyzes AWS folder rights.
    :param aws_storage_path: Path to AWS folder.
    :return: True if permissions are incorrect, otherwise False.
    """
    if not os.path.exists(aws_storage_path):
        print("Can't find AWS Key storage or permissions properly configured")
        return False
    files = os.listdir(aws_storage_path)
    if "credentials" not in files:
        print("Can't find AWS Key storage or permissions properly configured")
        return False
    aws_storage_path = os.path.join(aws_storage_path, "credentials")
    print("Analysing AWS keys storage...")
    if os.path.isfile(aws_storage_path):
        try:
            print("AWS Key storage exists, checking permissions...")
            perm = os.stat(aws_storage_path)
            rights_verdict = check_rights(
                perm, aws_storage_path)
            return rights_verdict
        except Exception:
            colour_print("AWS credentials file permission denied!", "green")
            return False
    else:
        print("Can't find AWS Key storage or permissions properly configured")
        return False


def print_aws_verdict(rights_verdict, aws_storage_path):
    """
    Prints result of AWS folder check.
    :param rights_verdict: Check result.
    :param aws_storage_path: Path to AWS folder.
    """
    if rights_verdict:
        colour_print("Your AWS key storage isn't secure.", "red")
        colour_print("Run `chmod 600 " + aws_storage_path + "credentials` to fix this issue.", "red")
    else:
        colour_print("Your AWS key storage is secure!", "green")


def analyze_privatekey_storage(key_folder):
    """
    Analyzes private key storage and encryption.
    :param key_folder: Path to key folder.
    :return unencrypted_keys_list, wrong_rights_list: List with unencrypted files, list with file with wrong rights.
    """
    if not os.path.exists(key_folder):
        print("Can`t find key directory")
        return
    print("Analysing keys storage...")
    unencrypted_keys_list = []
    wrong_rights_list = []
    for root, dirs, files in os.walk(key_folder):
        for key_file in files:
            file_rights_verdict = False
            file_path = os.path.join(root, key_file)
            try:
                permissions = os.stat(file_path)
                with open(file_path, "r") as f:
                    first_line = f.readline()
                    second_line = f.readline()
                    if "-----BEGIN OPENSSH PRIVATE KEY-----" in first_line:
                        file_rights_verdict = check_rights(permissions, key_file)
                        second_line_decoded = base64.b64decode(
                            second_line + "==")
                        if "bcrypt" not in second_line_decoded:
                            notify_unencrypted(file_path)
                            unencrypted_keys_list.append(file_path)
                        else:
                            notify_encrypted(file_path)
                    elif "-----BEGIN RSA PRIVATE KEY-----" in first_line:
                        file_rights_verdict = check_rights(permissions, key_file)
                        if "ENCRYPTED" in second_line:
                            notify_encrypted(file_path)
                        else:
                            notify_unencrypted(file_path)
                            unencrypted_keys_list.append(file_path)
                    elif key_file == "known_hosts":
                        file_rights_verdict = check_rights(permissions, key_file)
                if file_rights_verdict:
                    wrong_rights_list.append(file_path)
            except Exception:
                pass
    return unencrypted_keys_list, wrong_rights_list


def print_ssh_verdict(unencrypted_list, wrong_rights_list):
    """
    Prints result of key folder check.
    :param unencrypted_list: List with unencrypted files.
    :param wrong_rights_list: List with file with wrong rights.
    """
    if len(unencrypted_list) > 0 or len(wrong_rights_list) > 0:
        colour_print("Your SSH key storage isn't secure!", "red")
        if len(unencrypted_list) > 0:
            colour_print(
                "Some of your key files are unencrypted. Visit https://mackeepersecurity.com/post/kromtech-releases-key-inspector-free-tool-to-check-your-ssh-keys to find how to fix this..", "red")
            colour_print("The following files are unencrypted:", "red")
            for unencrypted_file in unencrypted_list:
                colour_print(unencrypted_file, "red")
        if len(wrong_rights_list) > 0:
            colour_print(
                "Some of your files have unnecessary permissions. This means that they might be accessed by any process launched with your user account", "red")
            file_names = ""
            for file_name in wrong_rights_list:
                file_names = file_names + " " + file_name
            colour_print("Run `chmod 600" + file_names +
                         "` to fix this issue.", "red")
    else:
        colour_print("Your SSH key storage is secure!", "green")


def colour_print(message, colour):
    """
    Coloured print snippet
    :param message: Message to print.
    :param colour: Colour to print message in.
    """
    termcolor.cprint(termcolor.colored(
        message, colour, attrs=["bold"]))


def check_rights(perm, file_name):
    """
    Checks if file has some unneeded rights set.
    :param perm: File permissions.
    :param file_name: File path.
    :return: True, if file has unneeded rights
    """
    unneeded_rights = {
        "Group read": stat.S_IRGRP,
        "Everyone read": stat.S_IROTH,
        "User execute": stat.S_IXUSR,
        "Group execute": stat.S_IXGRP,
        "Group write": stat.S_IWGRP,
        "Everyone write": stat.S_IWOTH,
        "Everyone execute": stat.S_IXOTH
    }
    rights_verdict = False
    for right_name in unneeded_rights:
        # permission check procedure
        permission = bool(perm.st_mode & unneeded_rights[right_name])
        rights_verdict += permission
        if permission:
            colour_print("Your '" + file_name + "' file has '" +
                         right_name + "' right set up!", "yellow")
    return rights_verdict


def notify_encrypted(file_name):
    """
    Prints message for encrypted file.
    :param file_name: Filename
    """
    colour_print("Key '" + file_name +
                 "' is encrypted.", "green")


def notify_unencrypted(file_name):
    """
    Prints message for unencrypted file.
    :param file_name: Filename
    """
    colour_print("Your '" + file_name +
                 "' key is unencrypted!", "yellow")


def print_verdict(aws_rights_verdict, aws_storage_path, unencrypted_list, wrong_rights_list, mode):
    """
    Prints overall verdict for all checks.
    :param aws_rights_verdict: Result of AWS permissions check.
    :param aws_storage_path: Path to AWS folder.
    :param unencrypted_list: List with unencrypted files.
    :param wrong_rights_list: List with files, with wrong permissions set.
    :param mode: Script run mode.
    """
    print("")
    if aws_rights_verdict or len(wrong_rights_list) > 0 or len(unencrypted_list) > 0:
        colour = "red"
    else:
        colour = "green"
    colour_print(20 * "*" + "  S U M M A R Y  " + 20 * "*", colour)
    if mode in ("all", "aws"):
        print_aws_verdict(aws_rights_verdict, aws_storage_path)
    if mode in ("all", "ssh"):
        print_ssh_verdict(unencrypted_list, wrong_rights_list)


def main():
    home = os.path.expanduser("~")
    packages = ["termcolor", ]
    for package in packages:
        install_and_import(package)
    aws_rights_verdict = False
    aws_storage_path = ""
    unencrypted_list = []
    wrong_rights_list = []
    colour_print(
        20 * "*" + "  W E L C O M E  T O  K E Y  I N S P E C T O R  " + 20 * "*", "yellow")
    mode = input(
        "What kind of check you want to perform (aws|ssh|all)? [all]: ") or "all"
    if mode in ("all", "ssh"):
        ssh_dir = input(
            "Enter your keys directory or press enter for the default path [HOME]: ") or home
        unencrypted_list, wrong_rights_list = analyze_privatekey_storage(
            ssh_dir)
    if mode in ("all", "aws"):
        aws_storage_path = input(
            "Enter your aws credentials directory or press enter for the default path [~/.aws/]: ") or os.path.join(home, ".aws/")
        aws_rights_verdict = analyze_aws(aws_storage_path)
    print_verdict(aws_rights_verdict, aws_storage_path, unencrypted_list, wrong_rights_list, mode)

if __name__ == "__main__":
    main()

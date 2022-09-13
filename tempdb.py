def gen_help_string():
    help_string = """Here are a list of commands and their functions:

C:
<b>clear</b>: clears all previous commands from the terminal

H:
<b>help</b>: brings up this help menu

L:
<b>logout</b>: allows user to logout from terminal

S:
<b>spotify login</b>: logs you in through spotify
<b>spotify merge "<first_playlist_name>" "<second_playlist_name>" ... "<new_playlist_name>"</b>: merges the first n - 1 playlists and creates a new one with name new_playlist_name
<b>spotify playlists</b>: lists all playlists of the current user, along with links

"""
    #split_string = help_string.split("\n")
    return help_string

import os

locales = os.environ.get('LOCALES', 'PL').upper()

new_action_available = {
    "EN": "New action with your participation has been created. Check details on action list.",
    "PL": "Dodano nową akcję z twoim udziałem. Sprawdź szczegóły na liście akcji."
}

new_point_added = {
    "EN": "New special point has been added to map of current action. Check it out on map view.",
    "PL": "Pojawił się nowy punkt specjalny w obrębie akutalnej akcji. Sprawdź mapę po więcej..."
}

new_area_for_you = {
    "EN": "New area has been assign to you. Please explore details inside the application.",
    "PL": "Zostałeś przypisany do nowego obszaru. Przejdź do aplikacji aby sprawdzić szczegóły."
}

action_is_active_now = {
    "EN": "One of your actions is now active. Feel free to join it and become a rescuer.",
    "PL": "Jedna z twoich akcji jest już aktywna! Przejdź do aplikacji aby móc do niej dołączyć."
}

sms_invite = {
    "EN": "You have been invited to join Search & Rescue app. Your login code: ",
    "PL": "Możesz się już zalogować do apliakcji Search & Rescue. Twój kod logowania: "
}

new_chat = {
    "PL": "Nowa wiadomość: ",
    "EN": "New message: "
}


def get_current_locales():
    if locales.upper() in ("PL", "EN"):
        return locales.upper()
    else:
        return "PL"

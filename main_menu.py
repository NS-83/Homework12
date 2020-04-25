import json
from GitHubParsing import get_data
search_settings = {'search_user': '',
                   'search_repository': '',
                   'search_organisation': '',
                   }


def users_input(number_of_items):
    choice = 0
    while choice not in range(1, number_of_items):
        try:
            choice = int(input('Введите номер пункта меню: '))
        except ValueError:
            pass
    return choice


def print_main_menu():
    print(f'Пользователь: {search_settings["search_user"]}')
    print(f'Репозиторий: {search_settings["search_repository"]}')
    print(f'Организация: {search_settings["search_organisation"]}')
    print('\n')
    print('1) Изменить настройки поиска')
    print('2) Поиск и формирование файлов')
    print('3) Выход')


def print_options_menu():
    print('1) Изменить пользователя')
    print('2) Изменить репозиторий')
    print('3) Изменить организацию')
    print('4) Вернуться в главное меню')
    chosen_options_menu_item = 0
    while chosen_options_menu_item != 4:
        chosen_options_menu_item = users_input(5)
        if chosen_options_menu_item == 1:
            search_settings["search_user"] = input('Введите пользователя: ')
        elif chosen_options_menu_item == 2:
            if search_settings["search_user"] == '':
                print('Необходимо указать пользователя')
                print_options_menu()
            else:
                search_settings["search_repository"] = input('Введите репозиторий: ')
        elif chosen_options_menu_item == 3:
            search_settings["search_organisation"] = input('Введите организацию: ')


if __name__ == '__main__':
    print_main_menu()
    chosen_menu_item = 0
    while chosen_menu_item != 3:
        chosen_menu_item = users_input(4)
        if chosen_menu_item == 1:
            print_options_menu()
            print('\n')
            print_main_menu()
        elif chosen_menu_item == 2:
            result = get_data(search_settings)
            if result['errors']:
                for parser_error in result['errors']:
                    print(parser_error)
            elif result['files']:
                result_file = open('Unsafe files', 'w')
                json.dump(result['files'], result_file, ensure_ascii=False, indent=2)
                result_file.close()
                print("Создан файл с данными об уязвимостях 'Unsafe files'")
            else:
                print('Не найдено потенциально опасных файлов.')

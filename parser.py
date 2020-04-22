import requests
import base64
import re

URL_TEMPLATE = 'https://api.github.com/search/code?q={word}+in:file+language:{lang}{search_area}' \
               '&per_page={amount_of_elements}'
# Количество элементов на странице. Максимум 100
ELEMENTS_PER_PAGE = 100
ERROR_STRING = 'Не удалось получить данные для языка {0} при поиске по ключевому слову {1}. Код ошибки {2}'
USER_NAME = 'NS83'
TOKEN = ''
WARNING = 'Потенциально опасен'
ERROR = 'Есть уязвимость'
WARNING_DESCRIPTION = 'испольуется {0}'
ERROR_DESCRIPTION = 'испольуется {0} с данными из внешнего источника'


def form_request_string(language, search_settings, search_word):
    if search_settings['search_organisation'] != '':
        search_area_string = f'+org:{search_settings["search_organisation"]}'
    elif search_settings['search_repository'] != '':
        search_area_string = f'+repo:{search_settings["search_user"]}/{search_settings["search_repository"]}'
    elif search_settings["search_user"] != '':
        search_area_string = f'+user:{search_settings["search_user"]}'
    else:
        search_area_string = ''
    return URL_TEMPLATE.format(word=search_word, lang=language, search_area=search_area_string,
                               amount_of_elements=ELEMENTS_PER_PAGE, )


def get_files(result, session):
    files_data = []
    if not result.links:
        get_files_data_from_page(files_data, result)
    else:
        last_page = False
        while not last_page:
            result = session.get(result.links['next']['url'])
            get_files_data_from_page(files_data, result)
            last_page = not result.links.get('next')
    for file in files_data:
        file_content = session.get(file['file_url'])
        file_bytes = base64.b64decode(file_content.json()['content'])
        file_strings = file_bytes.decode('utf-8').split('\n')
        file['file_strings'] = file_strings
    return files_data


def get_files_data_from_page(files_data, result):
    for item in result.json()['items']:
        if not item['path'].startswith('venv'):
            file_data = {'file_name': item['name'],
                         'repository': item['repository']['full_name'],
                         'file_url': item['url'],
                         'file_strings': ''}
            files_data.append(file_data)


def get_file_strings(file_content):
    file_bytes = base64.b64decode(file_content.json()['content'])
    file_strings = file_bytes.decode('utf-8').split('\n')
    return file_strings


def get_data(search_settings):
    result = {'errors': [],
              'files': {}}
    session = requests.session()
    session.auth = (USER_NAME, TOKEN)
    python_analysis(session, search_settings, result)
    return result


def python_analysis(session, search_settings, result):
    search_words = (('eval', eval_analysis), ('pickle', pickle_analysis))
    for search_word in search_words:
        search_string_eval = form_request_string('python', search_settings, search_word[0])
        query_result = session.get(search_string_eval)
        if query_result.status_code != 200:
            result['errors'].append(ERROR_STRING.format('python', 'eval', query_result.status_code))
        else:
            analysis_func = search_word[1]
            files_for_analysis = get_files(query_result, session)
            for file in files_for_analysis:
                analysis_func(file, result)


def get_param_from_function_string(func_string):
    first_bracket = func_string.find(')')
    first_comma = func_string.find(',')
    if first_bracket == -1:
        return None
    elif first_comma == -1:
        param_end = first_bracket
    else:
        param_end = min(first_bracket, first_comma)
    return func_string[:param_end]


def eval_analysis(file, result):
    file_strings = file['file_strings']
    file_strings.reverse()
    for str_number in range(len(file_strings)):
        file_line = file_strings[str_number]
        eval_position = file_line.find('eval')
        if eval_position != -1:
            param_string = get_param_from_function_string(file_line[eval_position + 5:])
            if not param_string:
                continue
            if param_string.startswith("'") or param_string.startswith("'"):
                # Если в строке, переданной в eval, есть read или input, считаем это уязвимостью.
                if param_string.find('input') + param_string.find('read') != -2:
                    add_file_to_result(result['files'], file['repository'], file['file_name'],
                                       ERROR_DESCRIPTION.format('eval'), ERROR)
                else:
                    add_file_to_result(result['files'], file['repository'], file['file_name'],
                                       WARNING_DESCRIPTION.format('eval'),
                                       WARNING)
            else:
                file_part = file_strings[str_number:]
                if param_from_outer_source(file_part, param_string):
                    add_file_to_result(result['files'], file['repository'], file['file_name'],
                                       ERROR_DESCRIPTION.format('eval'), ERROR)


def pickle_analysis(file, result):
    file_strings = file['file_strings']
    pickle_imported = False
    outer_source = False
    for file_string in file_strings:
        if file_string.find('import pickle') != -1:
            pickle_imported = True
            break
    if pickle_imported:
        file_strings.reverse()
        for str_number in range(len(file_strings)):
            file_line = file_strings[str_number]
            pickle_position = file_line.find('pickle.load')
            if pickle_position != -1:
                param_string = get_param_from_function_string(file_line[pickle_position + 12:])
                if not param_string:
                    continue
                file_part = file_strings[str_number:]
                outer_source = param_from_outer_source(file_part, param_string)
    if outer_source:
        add_file_to_result(result['files'], file['repository'], file['file_name'],
                            ERROR_DESCRIPTION.format('pickle'), ERROR)
    elif pickle_imported:
        add_file_to_result(result['files'], file['repository'], file['file_name'],
                           WARNING_DESCRIPTION.format('eval'),
                           WARNING)


def param_from_outer_source(file_part, param):
    # очень хотелось всё сделать на regexp, но не получилось, поэтому оставил простой анализ.
    for file_string in file_part:
        if file_string.find(param) != -1 and (file_string.find('input') != -1 or file_string.find('read') != -1
                                              or file_string.find('open') != -1):
            return True


def add_file_to_result(result, repository, file_name, code_type, status):
    repository_files = result.setdefault(repository, [])
    unsafe_module_data = {
        'name': file_name,
        'unsafe code type': code_type,
        'status': status
    }
    repository_files.append(unsafe_module_data)

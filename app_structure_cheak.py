import os
import argparse

DEFAULT_IGNORE = {
    '__pycache__',
    '.git',
    '.vscode',
    '.idea',
    'venv',
    'env',
    '.env',
    '.DS_Store',
    '*.pyc',
    '*.log',
    'Thumbs.db'
    'other',
    'certs_req',
    'Upload',
    'other',
    'logs'
}

def is_ignored(path, ignore_set):
    """Проверяет, должен ли путь быть проигнорирован."""
    basename = os.path.basename(path)
    return basename in ignore_set or any( pattern in basename or 
        basename == pattern or basename.startswith(pattern.rstrip('*'))
        for pattern in ignore_set
    )

def print_tree(startpath, ignore_set=None, prefix=''):
    if ignore_set is None:
        ignore_set = DEFAULT_IGNORE

    if not os.path.isdir(startpath):
        print(f"Путь не найден: {startpath}")
        return

    try:
        items = sorted(os.listdir(startpath))
    except PermissionError:
        print(f"{prefix}├── [Нет доступа]")
        return

    # Фильтруем игнорируемые элементы
    filtered_items = [item for item in items if not is_ignored(os.path.join(startpath, item), ignore_set)]

    for i, item in enumerate(filtered_items):
        path = os.path.join(startpath, item)
        is_last = i == len(filtered_items) - 1
        connector = '└── ' if is_last else '├── '

        print(prefix + connector + item)

        if os.path.isdir(path):
            extension = '    ' if is_last else '│   '
            print_tree(path, ignore_set, prefix + extension)

def main():
    parser = argparse.ArgumentParser(description="Вывод структуры проекта в виде дерева")
    parser.add_argument('path', nargs='?', default='.', help="Корневая директория проекта (по умолчанию — текущая)")
    parser.add_argument('--ignore', nargs='*', help="Список имён папок/файлов для игнорирования", default=[])
    args = parser.parse_args()

    ignore_set = set(DEFAULT_IGNORE)
    if args.ignore:
        ignore_set.update(args.ignore)

    print(args.path)
    print_tree(args.path, ignore_set)

if __name__ == '__main__':
    main()
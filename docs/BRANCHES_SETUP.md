# Настройка веток Git

Проект Flamix разделен на три независимые ветки для сервера, клиента и приложения.

## Структура веток

- **`server`** - Серверная часть (директория `server/`)
- **`client`** - Клиентская часть (директория `client/`)
- **`app`** - GUI приложение (директория `app/`)
- **`plugins`** - Плагины для различных файрволов (директория `plugins/`)
- **`master`** - Документация и вики (директория `docs/`)

## Настройка репозитория

### 1. Создание веток

```bash
# Создать ветку для сервера
git checkout -b server
git add server/
git commit -m "Add server branch"

# Создать ветку для клиента
git checkout -b client
git add client/
git commit -m "Add client branch"

# Создать ветку для приложения
git checkout -b app
git add app/
git commit -m "Add app branch"

# Создать ветку для плагинов
git checkout -b plugins
git add plugins/
git commit -m "Add plugins branch"

# Вернуться в master для документации
git checkout master
git add docs/ README.md
git commit -m "Add documentation"
```

### 2. Настройка .gitignore

Создайте `.gitignore` в корне проекта:

```gitignore
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual environments
venv/
env/
ENV/
.venv

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# Flamix specific
data/
certs/
logs/
*.db
*.db-shm
*.db-wal

# OS
.DS_Store
Thumbs.db
```

### 3. Работа с ветками

#### Переключение между ветками

```bash
# Переключиться на ветку сервера
git checkout server

# Переключиться на ветку клиента
git checkout client

# Переключиться на ветку приложения
git checkout app

# Вернуться в master
git checkout master
```

#### Пуш веток в удаленный репозиторий

```bash
# Настроить удаленный репозиторий (если еще не настроен)
git remote add origin <repository-url>

# Запушить все ветки
git push -u origin server
git push -u origin client
git push -u origin app
git push -u origin plugins
git push -u origin master
```

#### Обновление веток

```bash
# Обновить конкретную ветку
git checkout server
git pull origin server

# Обновить все ветки
git checkout server && git pull origin server
git checkout client && git pull origin client
git checkout app && git pull origin app
git checkout plugins && git pull origin plugins
git checkout master && git pull origin master
```

## Рекомендации

### Коммиты

- Делайте коммиты в соответствующую ветку
- Не смешивайте изменения из разных веток
- Используйте понятные сообщения коммитов

### Синхронизация общих модулей

Если вы изменили общие модули (например, `common/`), вам нужно:

1. Закоммитить изменения в одной ветке
2. Создать патч или cherry-pick в другие ветки
3. Или вручную скопировать изменения

### Документация

- Документация находится в ветке `master`
- Обновляйте документацию при изменении функциональности
- Используйте `docs/` для подробной документации

## Примеры работы

### Разработка сервера

```bash
git checkout server
# Внести изменения в server/
git add server/
git commit -m "Add new feature"
git push origin server
```

### Разработка клиента

```bash
git checkout client
# Внести изменения в client/
git add client/
git commit -m "Fix connection issue"
git push origin client
```

### Разработка плагинов

```bash
git checkout plugins
# Внести изменения в plugins/
git add plugins/
git commit -m "Add new plugin"
git push origin plugins
```

### Обновление документации

```bash
git checkout master
# Обновить docs/ или README.md
git add docs/ README.md
git commit -m "Update documentation"
git push origin master
```

## Клонирование конкретной ветки

Если вы хотите клонировать только одну ветку:

```bash
# Клонировать только ветку server
git clone -b server <repository-url> flamix-server

# Клонировать только ветку client
git clone -b client <repository-url> flamix-client

# Клонировать только ветку app
git clone -b app <repository-url> flamix-app

# Клонировать только ветку plugins
git clone -b plugins <repository-url> flamix-plugins
```

## Troubleshooting

### Конфликты при слиянии

Если возникли конфликты при слиянии веток:

1. Разрешите конфликты вручную
2. Используйте `git add` для разрешенных файлов
3. Завершите слияние `git commit`

### Откат изменений

```bash
# Откатить последний коммит (не изменяя файлы)
git reset --soft HEAD~1

# Откатить последний коммит (изменяя файлы)
git reset --hard HEAD~1
```

## Дополнительные ресурсы

- [Git Branching](https://git-scm.com/book/en/v2/Git-Branching-Branches-in-a-Nutshell)
- [Git Workflows](https://www.atlassian.com/git/tutorials/comparing-workflows)

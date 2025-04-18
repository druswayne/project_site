// Функция для защиты элемента от копирования
function protectContent(element) {
    if (!element) return;
    
    // Запрет контекстного меню
    element.addEventListener('contextmenu', function(e) {
        e.preventDefault();
        return false;
    });
    
    // Запрет копирования
    element.addEventListener('copy', function(e) {
        e.preventDefault();
        return false;
    });
    
    // Запрет вырезания
    element.addEventListener('cut', function(e) {
        e.preventDefault();
        return false;
    });
    
    // Запрет перетаскивания
    element.addEventListener('dragstart', function(e) {
        e.preventDefault();
        return false;
    });
}

// Глобальная защита от сохранения и копирования
document.addEventListener('keydown', function(e) {
    // Ctrl+S / Command+S
    if ((e.ctrlKey || e.metaKey) && e.keyCode === 83) {
        e.preventDefault();
        return false;
    }
    
    // Ctrl+C / Command+C
    if ((e.ctrlKey || e.metaKey) && e.keyCode === 67) {
        e.preventDefault();
        return false;
    }
    
    // Ctrl+Shift+C / Command+Shift+C (инструменты разработчика)
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.keyCode === 67) {
        e.preventDefault();
        return false;
    }
}); 
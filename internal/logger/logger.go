package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
)

// SetupLogging настраивает логгер (slog) для вывода в stderr или в файл.
// В Go принято возвращать настроенный логгер, который затем передается в функции,
// или устанавливать его как дефолтный. Мы сделаем его дефолтным для простоты.
func SetupLogging(logFile string, level slog.Level) (*slog.Logger, error) {
	var writer io.Writer = os.Stderr

	if logFile != "" {
		file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		writer = file
	}

	// Настраиваем текстовый обработчик логов, похожий на питоновский формат
	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Убираем вывод ключа time, чтобы не дублировать (в slog он по умолчанию)
			// и меняем формат времени, если нужно, но дефолтный RFC3339 достаточно близок.
			return a
		},
	}

	handler := slog.NewTextHandler(writer, opts)
	logger := slog.New(handler)

	// Устанавливаем его как стандартный логгер для всего приложения
	slog.SetDefault(logger)

	return logger, nil
}

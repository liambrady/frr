;; Load clang-format plugin
(load "/usr/share/emacs/site-lisp/clang-format-14/clang-format.el")
(global-set-key (kbd "M-O 3 k") 'clang-format-region)

;; Line column mode and more
(add-hook 'c-mode-common-hook (lambda ()
  (display-fill-column-indicator-mode 1)
  (set-fill-column 80)
  (c-set-style "Linux")
;  (setq tab-width 4)
  ))
(column-number-mode)

;; Cleanup hooks
(add-hook 'before-save-hook 'delete-trailing-whitespace)

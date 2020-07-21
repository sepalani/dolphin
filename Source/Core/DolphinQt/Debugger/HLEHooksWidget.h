// Copyright 2020 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#pragma once

#include <QDockWidget>

#include "Common/CommonTypes.h"

class QCloseEvent;
class QGroupBox;
class QShowEvent;
class QTableWidget;
class QToolBar;

class HLEHooksWidget : public QDockWidget
{
  Q_OBJECT
public:
  explicit HLEHooksWidget(QWidget* parent = nullptr);
  ~HLEHooksWidget();

protected:
  void closeEvent(QCloseEvent*) override;
  void showEvent(QShowEvent* event) override;

private:
  void CreateWidgets();
  void ConnectWidgets();

  QToolBar* CreateToolBar();
  QGroupBox* CreateHookedInstructionsGroup();

  void ToolbarAddHook();
  void ToolbarEditHook();
  void ToolbarDeleteHook();
  void ToolbarDeleteSymbolHooks();
  void ToolbarPatchHLEFunctions();

  void Update();

  QTableWidget* m_hooked_instructions_table;
  QAction* m_add;
  QAction* m_edit;
  QAction* m_delete_hook;
  QAction* m_delete_symbol_hooks;
  QAction* m_patch_hle_functions;
};

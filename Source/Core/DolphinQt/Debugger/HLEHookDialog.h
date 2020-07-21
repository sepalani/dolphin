// Copyright 2020 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#pragma once

#include <QDialog>

class HLEHooksWidget;
class QHBoxLayout;

class HLEHookDialog : public QDialog
{
  Q_OBJECT
public:
  explicit HLEHookDialog(HLEHooksWidget* parent);

  void accept() override;

private:
  void CreateWidgets();
  void ConnectWidgets();

  QHBoxLayout* CreateHookType();
  QHBoxLayout* CreateHookFlag();
  QHBoxLayout* CreateHookTarget();  // Target (address, symbol name)
  QHBoxLayout* CreateHookFunction();
};

// Copyright 2020 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#include "DolphinQt/Debugger/HLEHookDialog.h"

#include <map>

#include <QComboBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QVBoxLayout>

#include "Core/HLE/HLE.h"
#include "DolphinQt/Debugger/HLEHooksWidget.h"

static const std::map<HLE::HookType, const char*> HLE_HOOK_TYPES{
    {HLE::HookType::Start, "Start"},
    {HLE::HookType::Replace, "Replace"},
    {HLE::HookType::None, "None"},
};

static const std::map<HLE::HookFlag, const char*> HLE_HOOK_FLAGS{
    {HLE::HookFlag::Debug, "Debug"},
    {HLE::HookFlag::Fixed, "Fixed"},
    {HLE::HookFlag::Generic, "Generic"}};

HLEHookDialog::HLEHookDialog(HLEHooksWidget* parent) : QDialog(parent)
{
  setWindowTitle(tr("HLE hook"));
  CreateWidgets();
  ConnectWidgets();
}

void HLEHookDialog::accept()
{
  QDialog::accept();
}

void HLEHookDialog::CreateWidgets()
{
  auto* layout = new QVBoxLayout;
  // Hook properties
  layout->addItem(CreateHookType());
  layout->addItem(CreateHookFlag());
  // Target (address, symbol name)
  layout->addItem(CreateHookTarget());
  // Function executed on hook (printf, custom, etc.)
  layout->addItem(CreateHookFunction());
  setLayout(layout);
}

void HLEHookDialog::ConnectWidgets()
{
}

QHBoxLayout* HLEHookDialog::CreateHookType()
{
  auto* layout = new QHBoxLayout;
  layout->addWidget(new QLabel(tr("Hook type")));
  layout->addWidget(new QComboBox());
  return layout;
}

QHBoxLayout* HLEHookDialog::CreateHookFlag()
{
  auto* layout = new QHBoxLayout;
  layout->addWidget(new QLabel(tr("Hook flag")));
  layout->addWidget(new QComboBox());
  return layout;
}

QHBoxLayout* HLEHookDialog::CreateHookTarget()
{
  auto* layout = new QHBoxLayout;
  layout->addWidget(new QLabel(tr("Target")));
  layout->addWidget(new QComboBox());
  return layout;
}

QHBoxLayout* HLEHookDialog::CreateHookFunction()
{
  auto* layout = new QHBoxLayout;
  layout->addWidget(new QLabel(tr("Hook function")));
  layout->addWidget(new QComboBox());
  return layout;
}

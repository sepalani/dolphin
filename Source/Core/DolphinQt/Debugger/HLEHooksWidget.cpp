// Copyright 2020 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#include "DolphinQt/Debugger/HLEHooksWidget.h"

#include <QGroupBox>
#include <QHeaderView>
#include <QString>
#include <QTableWidget>
#include <QToolBar>
#include <QVBoxLayout>

#include "Core/Core.h"
#include "Core/HLE/HLE.h"
#include "Core/PowerPC/PowerPC.h"
#include "DolphinQt/Debugger/HLEHookDialog.h"
#include "DolphinQt/Host.h"
#include "DolphinQt/Settings.h"

HLEHooksWidget::HLEHooksWidget(QWidget* parent) : QDockWidget(parent)
{
  setWindowTitle(tr("HLE hooks"));
  setObjectName(QStringLiteral("hlehooks"));

  setHidden(!Settings::Instance().IsHLEHooksVisible() ||
            !Settings::Instance().IsDebugModeEnabled());

  setAllowedAreas(Qt::AllDockWidgetAreas);

  CreateWidgets();

  auto& settings = Settings::GetQSettings();

  restoreGeometry(settings.value(QStringLiteral("hlehookswidget/geometry")).toByteArray());
  // macOS: setHidden() needs to be evaluated before setFloating() for proper window presentation
  // according to Settings
  setFloating(settings.value(QStringLiteral("hlehookswidget/floating")).toBool());

  ConnectWidgets();

  connect(Host::GetInstance(), &Host::UpdateDisasmDialog, this, &HLEHooksWidget::Update);

  connect(&Settings::Instance(), &Settings::HLEHooksVisibilityChanged, this,
          [this](bool visible) { setHidden(!visible); });

  connect(&Settings::Instance(), &Settings::DebugModeToggled, this, [this](bool enabled) {
    setHidden(!enabled || !Settings::Instance().IsThreadsVisible());
  });
}

HLEHooksWidget::~HLEHooksWidget()
{
  auto& settings = Settings::GetQSettings();

  settings.setValue(QStringLiteral("hlehookswidget/geometry"), saveGeometry());
  settings.setValue(QStringLiteral("hlehookswidget/floating"), isFloating());
}

void HLEHooksWidget::closeEvent(QCloseEvent*)
{
  Settings::Instance().SetHLEHooksVisible(false);
}

void HLEHooksWidget::showEvent(QShowEvent* event)
{
  Update();
}

void HLEHooksWidget::CreateWidgets()
{
  auto* widget = new QWidget;
  auto* layout = new QVBoxLayout;
  widget->setLayout(layout);
  layout->addWidget(CreateToolBar());
  layout->addWidget(CreateHookedInstructionsGroup());
  layout->addItem(new QSpacerItem(0, 0, QSizePolicy::Expanding, QSizePolicy::Expanding));
  setWidget(widget);
}

void HLEHooksWidget::ConnectWidgets()
{
}

QToolBar* HLEHooksWidget::CreateToolBar()
{
  auto toolbar = new QToolBar;
  toolbar->setContentsMargins(0, 0, 0, 0);
  toolbar->setToolButtonStyle(Qt::ToolButtonTextOnly);

  m_add = toolbar->addAction(tr("Add hook"), this, &HLEHooksWidget::ToolbarAddHook);
  m_edit = toolbar->addAction(tr("Edit hook"), this, &HLEHooksWidget::ToolbarEditHook);
  m_delete_hook = toolbar->addAction(tr("Delete hook"), this, &HLEHooksWidget::ToolbarDeleteHook);
  m_delete_symbol_hooks = toolbar->addAction(tr("Delete symbol's hooks"), this, &HLEHooksWidget::ToolbarDeleteSymbolHooks);
  m_patch_hle_functions = toolbar->addAction(tr("Patch HLE functions"), this, &HLEHooksWidget::ToolbarPatchHLEFunctions);
  
  m_add->setEnabled(false);
  m_edit->setEnabled(false);
  m_delete_hook->setEnabled(false);
  m_delete_symbol_hooks->setEnabled(false);
  m_patch_hle_functions->setEnabled(false);

  return toolbar;
}

QGroupBox* HLEHooksWidget::CreateHookedInstructionsGroup()
{
  QGroupBox* group = new QGroupBox(tr("Hooked instructions"));
  QGridLayout* layout = new QGridLayout;
  group->setLayout(layout);

  m_hooked_instructions_table = new QTableWidget();
  QStringList header{tr("Address"), tr("Symbol"), tr("Hook name"), tr("Hook type"),
                     tr("Hook flag")};
  m_hooked_instructions_table->setColumnCount(header.size());

  m_hooked_instructions_table->setHorizontalHeaderLabels(header);
  m_hooked_instructions_table->setTabKeyNavigation(false);
  m_hooked_instructions_table->verticalHeader()->setVisible(false);
  m_hooked_instructions_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_hooked_instructions_table->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_hooked_instructions_table->setSelectionMode(QAbstractItemView::SingleSelection);
  m_hooked_instructions_table->setWordWrap(false);
  m_hooked_instructions_table->setSortingEnabled(true);

  layout->addWidget(m_hooked_instructions_table, 0, 0);
  layout->setSpacing(1);
  return group;
}

void HLEHooksWidget::ToolbarAddHook()
{
  auto dialog = new HLEHookDialog(this);
  dialog->exec();
}

void HLEHooksWidget::ToolbarEditHook()
{
  auto dialog = new HLEHookDialog(this);
  dialog->exec();
}

void HLEHooksWidget::ToolbarDeleteHook()
{
  // TODO
  u32 addr = 0;
  HLE::UnPatch(addr);
}

void HLEHooksWidget::ToolbarDeleteSymbolHooks()
{
  // TODO
  u32 addr_start = 0;
  u32 addr_end = 0;
  for (u32 addr = addr_start; addr < addr_end; addr += 4)
    HLE::UnPatch(addr);
}

void HLEHooksWidget::ToolbarPatchHLEFunctions()
{
  HLE::PatchFunctions();
  Update();
}

void HLEHooksWidget::Update()
{
  if (!isVisible())
    return;

  m_add->setEnabled(false);
  m_edit->setEnabled(false);
  m_delete_hook->setEnabled(false);
  m_delete_symbol_hooks->setEnabled(false);
  m_patch_hle_functions->setEnabled(false);

  int i = 0;
  m_hooked_instructions_table->setRowCount(i);

  const auto state = Core::GetState();
  if (state != Core::State::Paused)
    return;

  m_add->setEnabled(true);
  m_patch_hle_functions->setEnabled(true);

  const auto get_address = [](u32 address) {
    return new QTableWidgetItem(QStringLiteral("%1").arg(address, 8, 16, QLatin1Char('0')));
  };
  const auto get_function_name = [](u32 address) {
    return new QTableWidgetItem(
        QString::fromStdString(PowerPC::debug_interface.GetDescription(address)));
  };
  const auto get_hook_name = [](u32 hook_index) {
    return new QTableWidgetItem(QLatin1Literal(HLE::GetFunctionNameByIndex(hook_index).data()));
  };
  const auto get_hook_type = [](u32 hook_index) {
    const auto hook_type = HLE::GetFunctionTypeByIndex(hook_index);
    switch (hook_type)
    {
    case HLE::HookType::Start:
      return new QTableWidgetItem(QLatin1Literal("Start"));
    case HLE::HookType::Replace:
      return new QTableWidgetItem(QLatin1Literal("Replace"));
    case HLE::HookType::None:
      return new QTableWidgetItem(QLatin1Literal("None"));
    default:
      return new QTableWidgetItem();
    }
  };
  const auto get_hook_flag = [](u32 hook_index) {
    const auto hook_flag = HLE::GetFunctionFlagsByIndex(hook_index);
    switch (hook_flag)
    {
    case HLE::HookFlag::Generic:
      return new QTableWidgetItem(QLatin1Literal("Generic"));
    case HLE::HookFlag::Debug:
      return new QTableWidgetItem(QLatin1Literal("Debug"));
    case HLE::HookFlag::Fixed:
      return new QTableWidgetItem(QLatin1Literal("Fixed"));
    default:
      return new QTableWidgetItem();
    }
  };

  for (const auto [address, hook_index] : HLE::GetHookedInstructions())
  {
    m_hooked_instructions_table->insertRow(i);
    m_hooked_instructions_table->setItem(i, 0, get_address(address));
    m_hooked_instructions_table->setItem(i, 1, get_function_name(address));
    m_hooked_instructions_table->setItem(i, 2, get_hook_name(hook_index));
    m_hooked_instructions_table->setItem(i, 3, get_hook_type(hook_index));
    m_hooked_instructions_table->setItem(i, 4, get_hook_flag(hook_index));
    i += 1;
  }
  m_hooked_instructions_table->resizeColumnsToContents();
  m_hooked_instructions_table->resizeRowsToContents();
}

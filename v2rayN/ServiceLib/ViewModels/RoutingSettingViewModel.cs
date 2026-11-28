namespace ServiceLib.ViewModels;

public partial class RoutingSettingViewModel : MyReactiveObject
{
    public Interaction<string, bool> ShowYesNoInteraction { get; } = new();
    public Interaction<string, RxVoid> SetClipboardDataInteraction { get; } = new();
    public Interaction<RxVoid, string?> ReadTextFromClipboardInteraction { get; } = new();

    #region Reactive

    public BulkObservableCollection<RoutingItemModel> RoutingItems { get; } = [];

    [Reactive]
    public partial RoutingItemModel SelectedSource { get; set; }

    public IList<RoutingItemModel> SelectedSources { get; set; }

    [Reactive]
    public partial string DomainStrategy { get; set; }

    [Reactive]
    public partial string DomainStrategy4Singbox { get; set; }

    public ReactiveCommand<RxVoid, RxVoid> RoutingAdvancedAddCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> RoutingAdvancedRemoveCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> RoutingAdvancedSetDefaultCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> RoutingAdvancedImportRulesCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> RoutingImportFromClipboardCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> RoutingExportSelectedCmd { get; }

    public bool IsModified { get; set; }

    #endregion Reactive

    public RoutingSettingViewModel()
    {
        _config = ConfigTextHandler.Config;

        var canEditRemove = this.WhenAnyValue(
            x => x.SelectedSource,
            selectedSource => selectedSource != null && !selectedSource.Remarks.IsNullOrEmpty());

        RoutingAdvancedAddCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            await RoutingAdvancedEditAsync(true);
        });
        RoutingAdvancedRemoveCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            await RoutingAdvancedRemoveAsync();
        }, canEditRemove);
        RoutingAdvancedSetDefaultCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            await RoutingAdvancedSetDefault();
        }, canEditRemove);
        RoutingAdvancedImportRulesCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            await RoutingAdvancedImportRules();
        });
        RoutingImportFromClipboardCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            await RoutingImportFromClipboardAsync(null);
        });
        RoutingExportSelectedCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            await RoutingExportSelectedAsync();
        }, canEditRemove);

        _ = Init();

        // Auto-save DomainStrategy when changed
        this.WhenAnyValue(
            x => x.DomainStrategy,
            x => x.DomainStrategy4Singbox)
            .Skip(1)
            .DistinctUntilChanged()
            .SubscribeAsync(async x =>
            {
                IsModified = true;
                await SaveSettingsAsync();
            });
    }

    private async Task Init()
    {
        SelectedSource = new();

        DomainStrategy = _config.RoutingBasicItem.DomainStrategy;
        DomainStrategy4Singbox = _config.RoutingBasicItem.DomainStrategy4Singbox;

        await ConfigDbHandler.InitBuiltinRouting();
        await RefreshRoutingItems();
    }

    #region Refresh Save

    public async Task RefreshRoutingItems()
    {
        var models = new List<RoutingItemModel>();

        var routings = await ConfigDbQuery.RoutingItems();
        foreach (var item in routings)
        {
            var it = new RoutingItemModel()
            {
                IsActive = item.IsActive,
                RuleNum = item.RuleNum,
                Id = item.Id,
                Remarks = item.Remarks,
                Url = item.Url,
                CustomIcon = item.CustomIcon,
                CustomRulesetPath4Singbox = item.CustomRulesetPath4Singbox,
                Sort = item.Sort,
            };
            models.Add(it);
        }
        RoutingItems.ReplaceRange(models);
    }

    /// <summary>
    /// Save DomainStrategy settings
    /// </summary>
    public async Task SaveSettingsAsync()
    {
        _config.RoutingBasicItem.DomainStrategy = DomainStrategy;
        _config.RoutingBasicItem.DomainStrategy4Singbox = DomainStrategy4Singbox;
        await ConfigTextHandler.SaveConfig();
    }

    #endregion Refresh Save

    public async Task RoutingAdvancedEditAsync(bool blNew)
    {
        RoutingItem item;
        if (blNew)
        {
            item = new();
        }
        else
        {
            item = await ConfigDbQuery.GetRoutingItem(SelectedSource?.Id);
            if (item is null)
            {
                return;
            }
        }
        var routingRuleSettingViewModel = new RoutingRuleSettingViewModel(item);
        if (await AppManager.Instance.WindowDialog.ShowDialogAsync(routingRuleSettingViewModel) == true)
        {
            await RefreshRoutingItems();
            IsModified = true;
        }
    }

    public async Task RoutingAdvancedRemoveAsync()
    {
        if (SelectedSource is null || SelectedSource.Remarks.IsNullOrEmpty())
        {
            NoticeManager.Instance.Enqueue(ResUI.PleaseSelectRules);
            return;
        }
        if (await ShowYesNoInteraction.HandleSafe(ResUI.RemoveServer) == false)
        {
            return;
        }
        foreach (var it in SelectedSources ?? [SelectedSource])
        {
            var item = await ConfigDbQuery.GetRoutingItem(it?.Id);
            if (item != null)
            {
                await ConfigDbHandler.RemoveRoutingItem(item);
            }
        }

        await RefreshRoutingItems();
        IsModified = true;
    }

    public async Task RoutingAdvancedSetDefault()
    {
        var item = await ConfigDbQuery.GetRoutingItem(SelectedSource?.Id);
        if (item is null)
        {
            NoticeManager.Instance.Enqueue(ResUI.PleaseSelectRules);
            return;
        }

        if (await ConfigDbHandler.SetDefaultRouting(item) == 0)
        {
            await RefreshRoutingItems();
            IsModified = true;
        }
    }

    private async Task RoutingAdvancedImportRules()
    {
        if (await ConfigDbHandler.InitRouting(true) == 0)
        {
            await RefreshRoutingItems();
            IsModified = true;
        }
    }

    #region Clipboard import/export

    public async Task RoutingExportSelectedAsync()
    {
        if (SelectedSource is null || SelectedSource.Remarks.IsNullOrEmpty())
        {
            NoticeManager.Instance.Enqueue(ResUI.PleaseSelectRules);
            return;
        }

        var sources = SelectedSources ?? [SelectedSource];
        var lst = new List<RoutingItem>();
        foreach (var it in RoutingItems)
        {
            if (!sources.Any(t => t?.Id == it.Id))
            {
                continue;
            }
            var item = await ConfigDbQuery.GetRoutingItem(it.Id);
            if (item != null)
            {
                lst.Add(item);
            }
        }
        if (lst.Count == 0)
        {
            return;
        }

        await SetClipboardDataInteraction.HandleSafe(RoutingExchangeHandler.Export(lst));
        NoticeManager.Instance.Enqueue(ResUI.OperationSuccess);
    }

    public async Task RoutingImportFromClipboardAsync(string? clipboardData)
    {
        var strData = clipboardData ?? await ReadTextFromClipboardInteraction.HandleSafe(RxVoid.Default);
        var items = RoutingExchangeHandler.Import(strData, ResUI.RoutingImportedRemarks);
        if (items == null || items.Count == 0)
        {
            NoticeManager.Instance.Enqueue(ResUI.OperationFailed);
            return;
        }

        var maxSort = RoutingItems.Count == 0 ? 0 : RoutingItems.Max(t => t.Sort);
        foreach (var item in items)
        {
            item.Sort = ++maxSort;
            if (await ConfigDbHandler.SaveRoutingItem(item) != 0)
            {
                NoticeManager.Instance.Enqueue(ResUI.OperationFailed);
                await RefreshRoutingItems();
                return;
            }
        }

        await RefreshRoutingItems();
        IsModified = true;
        NoticeManager.Instance.Enqueue(ResUI.OperationSuccess);
    }

    #endregion Clipboard import/export
}

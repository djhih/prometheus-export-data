# incident — 卡頓事件的蒐證與 postmortem

收到「昨天下午機器很卡」這類回報時,用 `incident_dump.py` 把那段時間 Prometheus 裡
所有相關的資料一次撈出來存檔,並產生一份照 Google SRE Book
[Example Postmortem](https://sre.google/sre-book/example-postmortem/) 格式的草稿。
能從資料得出的段落(影響、偵測、時間線、佐證)會自動填好,需要人判斷的段落
(根本原因、待辦事項、經驗)留給你寫。

## 前提

這支腳本查的是固定的一組 metric 名稱,對應下列 exporter。沒有的 exporter 會在
總覽表寫 `no data`,不影響其他部分;要換成自己的 metric 名稱,改 `build_catalog()`
裡的 query 就好。

| 來源 | metric 前綴 |
| --- | --- |
| [node_exporter](https://github.com/prometheus/node_exporter) | `node_*`(含 `node_pressure_*`,需要 pressure collector) |
| cgroup v2 exporter(自製) | `cgroup_*` |
| [cAdvisor](https://github.com/google/cadvisor) | `container_*` |
| NVML exporter(自製)/ [dcgm-exporter](https://github.com/NVIDIA/dcgm-exporter) | `nvml_*` / `DCGM_*` |
| SSH 探針(自製,從監控端量登入與指令延遲) | `ssh_probe_*` |
| 檔案同步 job 的 exporter(自製) | `ffds_sync_*` |

只有 Python 標準函式庫,不需要 pip。

## 快速開始

```bash
# 1. Prometheus / Grafana 只綁 127.0.0.1,先從監控主機拉 tunnel
ssh -N -L 9090:localhost:9090 -L 3000:localhost:3000 <monitoring-host> &

# 2. 撈資料(時間不帶時區就用本機時區;回報的時間抓個大概即可,前後會自動多撈 1h)
python3 incident_dump.py \
    --start "2026-09-10 14:00" --end "2026-09-10 16:00" --instance gpu-node-1

# 3. 補上 Prometheus 沒有的主機 log(journal、kernel OOM/hung task/XID、登入紀錄、sar)
cd incident-gpu-node-1-20260910-1400
ssh gpu-node-1 'bash -s' < collect-host-logs.sh > host-logs.txt

# 4. 編輯 postmortem.zh-tw.md
```

`--instance` 必須和 `prometheus.yml` 裡的 `instance` label **一字不差**;
打錯的話,報告的「資料完整性」那一段會直接寫「沒有 `up` series」。

如果 Prometheus 資料是複製出來的 TSDB(掛成本機 Prometheus,例如 9091),
加上 `--prom http://localhost:9091`。

## 參數

| 參數 | 預設 | 說明 |
| --- | --- | --- |
| `--start` / `--end` | 必填 | 回報的時間窗。接受 `2026-09-10 14:00`、RFC3339、unix 秒 |
| `--instance` | 必填 | 受影響主機的 `instance` label |
| `--pad` | `1h` | 時間窗前後多撈的範圍;**前面那段就是基準線** |
| `--tz` | 本機時區 | 報告使用的時區,例如 `+08:00` |
| `--prom` | `http://localhost:9090` | Prometheus 位址 |
| `--grafana` | `http://localhost:3000` | 只用來產生 dashboard 連結 |
| `--step` | 自動(≥ 15s) | 解析度。資料點上限是每個 series 11000 點,15s 可以涵蓋約 45 小時 |
| `--title` | `<instance> slowdown <時間>` | 草稿標題 |
| `--out` | `./incident-<instance>-<start>` | 輸出資料夾;已存在且非空時要加 `--force` |
| `--list` | | 只印出所有 PromQL,不連 Prometheus。可以拿去 Grafana Explore 貼上用 |

## 產出

```
incident-gpu-node-1-20260910-1400/
├── postmortem.zh-tw.md     草稿:AUTO 區塊已填,TODO 留給人寫
├── collect-host-logs.sh    在目標主機上跑,時間窗已經寫死在裡面
├── meta.json               參數、時間窗、Prometheus 版本與 retention、每個 query 的 PromQL 與結果
└── data/
    ├── <query>.json        Prometheus API 原始回應
    └── <query>.csv         攤平的表格(time, unix, labels..., value),可以直接丟 Excel
```

報告裡的每個數字都能從 `data/` 找到出處,也能用 `meta.json` 裡的 PromQL 重算。
Prometheus 只保留 15 天,**這個資料夾就是證據的正本**。

## 撈了哪些資料

| 區塊 | 來源 | 回答什麼 |
| --- | --- | --- |
| 資料完整性 | `up` | 那段時間每個 exporter 都有資料嗎?缺漏的時段不能拿來說「沒有負載」 |
| 使用者體感 | ssh-probe | 登入、登出、`cd`/`ls`/`poetry` 的延遲和失敗次數,是「卡頓」最客觀的量測 |
| 主機 | node-exporter | load、CPU、iowait、host PSI、記憶體、swap-in、磁碟忙碌、檔案系統、網路 |
| cgroup | cgroup-exporter | 每個 service / user 的 PSI、CPU、throttling、anon 記憶體、refault、direct reclaim、memory.high、OOM、IO、D-state |
| Container | cAdvisor | 每個 container 的 CPU、throttling、記憶體、OOM |
| GPU | nvml / DCGM | 使用率、記憶體、每個 user 的 GPU 記憶體、XID、PCIe replay |
| ffds-sync | ffds exporter | sync job 數量、讀寫量、D-state(只有 `--instance` 是 sync 主機時才有資料) |
| Alert | `ALERTS` | 那段時間有沒有 alert fire(所有主機) |
| 用量排行 | cgroup / cAdvisor / nvml | 窗內 CPU、RSS、IO 最高的 process(含 pid 和完整 command line)、cgroup、container |

某個 exporter 在這台主機上不存在(例如沒有 GPU),總覽表會寫 `no data`,不影響其他部分。
query 執行失敗會記在 `meta.json` 和總覽表的最後一欄,其他 query 會繼續跑。

## 判讀:門檻、基準線與限制

**「有變化的訊號」怎麼判定。** 每個 series 的門檻是
`max(固定下限, 2 × 基準線 p95)`,基準線是回報時間窗之前的 `--pad`(預設 1 小時)。
只要時間窗內有任何一點超過門檻,就算「有變化」,並以第一次越過門檻的時間放進時間線候選。

- 固定下限是為了壓掉雜訊,例如 `ls` 平常 20ms,就算翻倍也不算卡,所以下限設 500ms。
  各訊號的下限寫在 `build_catalog()` 的 `floor=`。
- 一直很高、但沒有「變化」的訊號不會被標出來(門檻會跟著基準線一起變高)。
  這種長期佔用資源的人要看「用量排行」。
- **使用者回報的時間通常不準。** 如果問題其實早就開始了,基準線會被污染、門檻偏高。
  看到時間線候選事件擠在時間窗最前面時,把 `--start` 往前移或把 `--pad` 加大,再跑一次。

**Prometheus 看不到的東西**(寫進報告的限制說明):

- gauge 每 15s 才取一次樣,比這更短的尖峰、或活不到 15s 的 process 可能沒被記到。
- `cgroup_top_process_*` 每個 user 只記前幾名,排名以外的 process 不會出現。
- 資料完整性表用的是 `min_over_time(up[60s])`,短於約一分鐘的中斷會被模糊掉。
- 使用者電腦到主機的網路、NFS/SMB 伺服器端的狀況,這套監控都量不到。
  這時就要靠 `host-logs.txt`(kernel log 裡的 `nfs` / `cifs` / `hung_task` 訊息)。

## 怎麼寫 postmortem

### 原則

- **Blameless。** 寫「系統為什麼允許這件事發生」,不寫「誰做錯了」。
  提到某個使用者的 process,是為了找出機制(例如缺少 memory limit),不是為了究責。
- **每個說法都附證據。** 數字要有時間點和出處,例如「14:32 `ls` 延遲 4.6s
  (`data/ssh_command.csv`)」。
- **分清楚事實和推論。** 例如「alice 的 anon 記憶體在 14:05 開始上升」是事實;
  「因此擠掉了 page cache」是推論,推論要說明依據。

### 各段落寫什麼

| 段落 | 要回答的問題 | 資料從哪來 |
| --- | --- | --- |
| 摘要 | 一兩句:什麼壞了、多久、影響誰 | 其他段落寫完後最後寫 |
| 影響 | 誰、在做什麼時、感受到什麼、多久、有沒有 job 失敗或要重跑 | AUTO 的 ssh-probe 數字、使用者原話、登入人數 |
| 根本原因 | 機制是什麼?為什麼系統允許它發生? | 「有變化的訊號」+「用量排行」+ `host-logs.txt` |
| 觸發條件 | 哪個事件讓潛在問題浮現? | 時間線上最早的那個變化 |
| 處置 | 怎麼恢復的?有人介入還是自己好的? | 時間線上訊號回落的時間、操作紀錄 |
| 偵測 | 怎麼知道的?監控最早什麼時候看到? | AUTO 的 alert 紀錄、「最早越過門檻的訊號」、使用者回報時間 |
| 待辦事項 | 怎麼防止再發生? | 從根本原因和「做得不好的地方」推出來 |
| 經驗 | 做得好的 / 做得不好的 / 運氣好的 | 回顧整個處理過程 |
| 時間線 | 按時間排列的事實 | AUTO 候選事件 + 人為事件 |
| 佐證資料 | 讓讀者自己驗證 | 全部 AUTO |

### 範例寫法(虛構情境,只示範寫法)

> **摘要**:2026-09-10 14:05–14:40,gpu-node-1 上一個訓練 job 的記憶體從 4 GiB 漲到
> 184 GiB,整台機器陷入記憶體壓力,互動操作(登入、`ls`)延遲升到 5–10 秒,持續約 35 分鐘,
> 直到該 job 被 OOM killer 終止。
>
> **影響**:當時有 7 個帳號登入。ssh-probe 量到登入時間最高 6.6s(平常 0.3s),
> `ls` 最高 4.6s(平常 22ms),超過門檻共 30 分鐘。有一位使用者回報 notebook 無回應。
>
> **根本原因**:user slice 沒有設定 `MemoryHigh` / `MemoryMax`,單一 process 可以用掉
> 整台機器的記憶體。記憶體被 anon page 佔滿後,其他使用者的 page cache 被回收,
> 一般指令也要等 direct reclaim,所以整台機器都變慢(cgroup memory PSI some 68%)。
>
> **觸發條件**:14:05 開始的 `train.py --workers 64`,每個 worker 各自載入一份完整資料集。
>
> **待辦事項**:
>
> | 待辦事項 | 類型 | 負責人 | 追蹤 |
> | --- | --- | --- | --- |
> | 對 user slice 設 `MemoryHigh`,讓超量的人自己變慢,不拖垮別人 | prevent | ○○ | #123 |
> | 啟用 memory PSI alert(Prometheus rule 檔裡已有範例) | process | ○○ | #124 |
> | 在使用說明加上 DataLoader worker 的記憶體注意事項 | mitigate | ○○ | #125 |

### 時間線

AUTO 產生的是**候選事件**,不是結論。整理方式:

1. 刪掉跟這次無關的條目。例如別台主機的 alert,或本來就有的雜訊。
2. 補上人為事件:使用者什麼時候開始覺得慢、什麼時候回報、誰看了什麼、做了什麼處置。
3. 在真正的開始和結束加上 **事件開始** / **事件結束** 標記。它們常常和「回報的時間窗」不同。
4. 全部用同一個時區(草稿標頭會寫是哪一個)。

### 待辦事項

- 類型分三種:**mitigate**(降低影響)、**prevent**(防止再發生)、**process**(流程、告警、文件)。
- 每一項都要有負責人和追蹤連結,並且對應到某個根本原因或「做得不好的地方」。
- 常見的 process 類待辦:「這次沒有 alert,是使用者隔天回報才知道」。
  每份 postmortem 裡的 PSI 峰值,都是之後訂 alert 門檻的真實依據
  (PSI rule 常常就是在等這種基準資料)。

### 保留圖表

Prometheus 資料 15 天後就會刪除。草稿裡的 Grafana 連結已經鎖定時間窗,
定稿前逐一打開,選 **Share → Snapshot**,expire 選 **Never**,把 snapshot 連結貼回報告。

## 資料安全

輸出資料夾裡有**使用者名稱、完整 command line、主機名稱**。repo 是公開的:

- 輸出資料夾不要放進 repo。`.gitignore` 已經有 `incident-*/`,但改過 `--out` 的路徑就不在保護範圍內。
- 報告要分享到 repo 或公開管道之前,先遮蔽主機名、使用者名稱、路徑和 command line。

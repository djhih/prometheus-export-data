# 卡頓事件處理流程

收到「某台機器很卡」的回報時,從頭到尾該做什麼。角色分工假設如下,不同就自行替換:

- **monitor** — Prometheus 和這套工具所在的主機
- **jump** — 跳板機,monitor 連不到目標主機時用它中繼
- **目標主機** — 被回報卡頓的那台

## 時效:15 天

Prometheus 預設保留 15 天。**事件日 + 15 天**就是最後期限,過了只剩下已經撈出來的資料夾。
主機的 journal 和 sar 常常更短(有些系統只有 7 天),所以 log 要更早撈。

收到回報的當天就先做步驟 1,報告可以晚點寫。

## 0. 先記下回報內容(五分鐘)

這決定後面要看哪些訊號,而且事後補問常常問不到了:

- **誰**回報、透過什麼管道(原話照抄)
- **什麼時候**開始、持續多久
- **在做什麼**的時候卡:ssh 登入?`ls`?跑訓練?開 notebook?
- 有沒有**工作失敗或需要重跑**

## 1. 撈 Prometheus

```bash
cd ~/incidents
python3 ~/prometheus-export-data/incident_dump.py \
    --start "2026-10-01 16:30" --end "2026-10-01 16:40" \
    --instance <目標主機的 IP 或主機名> --tz +08:00
```

- **`--tz` 不要省**:伺服器常常是 UTC,少了它時間會整個跑掉。
- **`--instance` 不用帶 port**,腳本會同時比對 `主機` 和 `主機:port`。
- 時間抓個大概就好,前後會自動各多撈 1 小時,前面那段當基準線。
- 產出在 `~/incidents/incident-<主機>-<日期>-<時間>/`。

跑完先確認沒有 query 失敗:

```bash
cd incident-<主機>-<日期>-<時間>
jq -r '.queries[] | select(.error) | "ERROR \(.id): \(.error)"' meta.json
sed -n '/### 資料完整性/,/^Resolution/p' postmortem.zh-tw.md
```

資料完整性表裡有 job 整段 down,代表那部分的假設只能是「無法判斷」,不是「沒問題」。

## 2. 撈主機 log

Prometheus 沒有 log,OOM、hung task、NFS 逾時、GPU XID 只存在 kernel log 裡。

**monitor 連得到目標主機**:

```bash
ssh <目標主機> 'bash -s' < collect-host-logs.sh > host-logs.txt      # 不需要 sudo
```

**要經過跳板機**:編輯 `collect-via-jump.sh` 開頭四個變數,在 jump 上執行。

**家目錄壞掉或只能手動登入**:在目標主機上 `cd /tmp` 後手動執行腳本,輸出存到 `/tmp`,
再逐段 scp 回來。撈完記得刪掉暫存,log 裡有使用者名稱和完整 command line。

## 3. 把 log 併進報告,重跑

```bash
INC=~/incidents/incident-<主機>-<日期>-<時間>
cd ~/incidents && python3 ~/prometheus-export-data/incident_dump.py \
    --start ... --end ... --instance ... --tz +08:00 --force \
    --out $INC --host-logs $INC/host-logs.txt
```

排查清單會把 log 的證據一起判定,命中的 log 行也會加進時間線。

## 4. 檢查卡住的 process 在等什麼

```bash
python3 ~/prometheus-export-data/stall_check.py $INC
```

| 輸出 | 意思 |
| --- | --- |
| 多個**不同使用者在同一秒**一起卡 | 共用資源出問題(網路檔案系統、儲存服務) |
| 每次都只有一個使用者、時間分散 | 零星等待,背景雜訊 |
| 卡住但自己幾乎沒有區塊 IO | 等的不是本機磁碟(區塊計數器不含 NFS / SMB) |
| 卡住的時刻和全機磁碟 IO 高峰**對齊** | 本機磁碟爭用 |

## 5. 寫報告

```bash
cp postmortem.zh-tw.md postmortem-final.zh-tw.md     # 手寫的放這份
```

**一定要另存。** 之後每次 `--force` 重跑都會覆蓋 `postmortem.zh-tw.md`。

填空順序(**摘要最後寫**):影響 → 時間線 → 根本原因 → 觸發條件 → 處置 → 偵測 →
待辦事項 → 經驗 → 摘要。

排查清單的四種結論要這樣用:

| 結論 | 在報告裡怎麼寫 |
| --- | --- |
| **已排除** | 寫進根本原因,附上「最高多少、門檻多少」 |
| **有跡象** | 逐條判斷是不是真的原因。有跡象不等於原因 |
| **無法判斷** | 寫進「做得不好的」,並且**每一條都對應一項待辦** |
| **需人工判斷** | 自己看表,和「有變化的訊號」對得起來才採用 |

找不到原因很正常。誠實寫「未確定」,把排除掉的和缺監控的列清楚,下次就不用重做同樣的排查。

## 6. 保存

1. **Grafana snapshot**:草稿裡的連結已鎖定時間窗,逐一開啟 → Share → Snapshot →
   expire 選 Never,把連結貼回報告。Prometheus 的資料會過期,snapshot 不會。
2. **備份整個資料夾**到自己的地方,共用帳號不保險。
3. **對外分享前遮蔽**主機名、IP、使用者名稱、路徑和 command line。

## 常見陷阱

這些都是實際踩過的:

- **「沒命中」不等於「沒發生」。** journal 如果沒保存到那段時間,grep 當然什麼都找不到。
  `host-logs.txt` 裡的 `entries in window:` 是 0 就代表 log 撈不到,相關假設一律「無法判斷」。
- **掛載表不是錯誤訊息。** `mount` 的輸出裡本來就有 `nfs`、`cifs` 字樣。
- **一個 process 進 D state 是常態。** 多使用者機器上隨時都有人在等 IO。
- **使用者講的時間通常不準。** 時間線的事件都擠在時間窗最前面,就是問題開始得更早,
  把 `--start` 往前移、`--pad` 加大重跑。
- **事後觀察到的現象不等於事發時的狀況。** 今天看到的異常要註明是事後補查。
- **用量最高的不一定是元凶。** 長期就在跑的工作不會造成「變化」。

## 跑第一次之前先確認

這些沒處理好,很多假設會直接變成「無法判斷」:

- [ ] 各 job 的 scrape target 都是通的(Prometheus 的 Targets 頁面沒有紅的)
- [ ] 目標主機有 node_exporter,而且開了 pressure collector(`node_pressure_*`)
- [ ] 有在量使用者體感的探針(登入、指令延遲),而且確定有資料
- [ ] 有 alert rule;沒有的話,偵測就只能靠使用者回報
- [ ] 家目錄或共用儲存如果是網路檔案系統,要有對應的延遲指標

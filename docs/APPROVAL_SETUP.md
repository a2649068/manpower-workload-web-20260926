# 人工核准部署與驗證

## 本次核對的範圍

2026-10-08：主分支 `0b8476bb843589d692c574beb5733ee3c5ab4395`。
公開 Auth settings：`disable_signup=false`、`mailer_autoconfirm=false`、email 登入開啟、anonymous users 關閉。
以 config.js 的公開 key 測試 REST schema 與兩個正式表的 `limit=0`，均回傳 401，沒有讀取正式資料。
401 不能證明 authenticated 使用者的 RLS 正確，也不能證明目前公開 key 可正常讀取 REST。
本次沒有 Supabase 管理連線、使用者 session、線上 SQL 或 sheet-reference 原始碼；**沒有核對到實際 RLS、RPC 定義、Edge Function 權限，也沒有修改線上資料庫**。
GitHub PR 只提供程式與部署材料，不表示後端保護已上線。

## 先稽核，再部署

1. 在 Supabase SQL Editor 執行 `supabase/audit.sql`，私下保留結果與備份。核對所有正式資料表、view、Storage、Edge Functions 與能讀寫正式資料的 RPC。這個 migration 只處理前端現有的 `assignments`、`summary_people` 及三個寫入 RPC；其他入口必須補相同授權。`SECURITY DEFINER`、owner view、service-role 路徑尤其需要檢查。確認 `approval_private` 不在 API exposed schemas 中。
2. 匯出目前 `sheet-reference` 原始碼與設定。在它既有 handler 中整合下方 guard，保留原 Google Sheet 同步邏輯與環境變數。**缺少這一步，Sheet 通訊錄／專案資料仍可能繞過核准；不可將前端 patch 視為部署完成。** 若無法取得 handler，暫緩切換，先取得原始碼。
3. 在 staging 執行 `supabase/migrations/202610080001_manual_approval.sql`。SQL 在 transaction 中執行，缺少正式表/RPC 或不支援的 RPC signature 會回滾。既有 RPC 移到 private schema，公開名稱由核准 wrapper 接手；保留其參數、回傳型態、業務實作及既有資料。不保證未知 RPC 的動態 SQL／schema 自省相容，須先核對稽核結果及 staging 測試。
4. 明確選定第一位已驗證管理者；不自動以第一個註冊者或所有舊使用者當管理者。用以下 SQL，以實際 UID 替換佔位。管理身分與正式資料核准分開；撤銷核准不撤銷管理身分。若要撤銷管理身分，在 SQL Editor 刪除 approval_admins 對應 UID。

```sql
begin;
-- Replace with a verified user's actual UID from Authentication > Users.
insert into public.approval_admins(user_id)
select id from auth.users where id = 'REPLACE_WITH_ACTUAL_UUID'::uuid
  and email_confirmed_at is not null on conflict do nothing;
insert into public.approved_users(user_id,approved_by)
select user_id,user_id from public.approval_admins
where user_id = 'REPLACE_WITH_ACTUAL_UUID'::uuid on conflict do nothing;
commit;
```

5. 確認兩張正式表的 authenticated DML privileges 與既有 permissive policies 足以讓已核准同仁工作。新增 restrictive policy 保留既有限制；只有表完全沒有 permissive policy 才建立 baseline。匿名權限及 authenticated TRUNCATE 等繞過 RLS 的權限被撤銷。
6. 在同一維護時段部署 SQL、已加 guard 的 sheet-reference 與前端；先讓管理者逐一核准應保留的舊帳號。其餘帳號會進入待核准狀態，舊資料不刪除。勿自動全員核准。
7. migration 將兩張正式表移出 `supabase_realtime` publication，改為只發布新的 `manpower_changes` 更新計數。statement trigger 在原表異動時更新計數，前端收到通知後照原方式重新載入，保留即時同步及一分鐘 Google Sheet 更新。這避免 Postgres Changes 的 DELETE 事件繞過逐列 RLS，向未核准訂閱者洩漏正式表主鍵。正式資料仍經 RLS 查詢。若另有舊版客戶端直接訂閱原表，它們也須換成新計數通知；本 repo 的新版前端已完成替換。稽核其他 publications 不得繼續發布這兩張正式表；FOR ALL TABLES 的 supabase_realtime 會讓 migration 中止，須先由管理者整理。

## sheet-reference 必須加入的實際整合

把本 PR 的 `_shared/approval.ts` 與原 handler 一起部署；以下兩處是對原始碼的必要修改。原 handler 若使用 `serve(...)` 也採同樣位置，保留既有 CORS 的 OPTIONS 回應。

```ts
import { requireApproval } from '../_shared/approval.ts';

Deno.serve(async (req) => {
  // Keep existing OPTIONS/CORS handling first. No data may be returned by OPTIONS.
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  const denied = await requireApproval(req, corsHeaders);
  if (denied) return denied;
  // Existing Sheet fetch/response logic continues here, unchanged.
});
```

使用 caller Bearer JWT 驗證 `getUser` 並查詢當下核准表，**不得以 service-role 查詢 has_approved_access**。Supabase_ANON_KEY 只存在 Edge 環境中；前端沒有新增任何 secret。若原 handler 另有快取，授權必須在回傳快取前執行。所有讀寫正式資料的其他 Edge handlers 也須加 guard。CORS 不是授權。

## 功能與權限驗收（staging 後再 production）

| 身分／狀態 | 正式表直接 REST | 三個寫入 RPC | Sheet Function | 管理名單／核准 RPC |
|---|---|---|---|---|
| 未登入 | 拒絕 | 拒絕 | 401 | 拒絕 |
| 未驗證 | 無正式資料／拒絕 | 拒絕 | 403 | 拒絕 |
| 已驗證未核准 | 無正式資料 | 42501，無變更 | 403 | 42501 |
| 已驗證已核准 | 依既有權限讀寫 | 原業務功能正常 | 原同步正常 | 非管理者 42501 |
| 管理者 | 仍須個別核准才能讀寫正式資料 | 同左 | 同左 | 可看人數名單／核准／撤銷 |
| 撤銷後原 JWT | 後續讀寫立即受新核准狀態約束 | 42501 | 403 | 非管理者拒絕 |

用不同 session 直接呼叫 API（繞過 UI）測試 INSERT/UPDATE/DELETE/SELECT、三個 RPC 與管理 RPC；已開始且通過授權的請求不保證被追溯取消，已下載／匯出資料不能追回。SQL 測試以 transaction+rollback 執行，不能用 production 真實資料做破壞測試。

前端每 30 秒重新核對核准狀態，撤銷後清空表格、停止資料同步與訂閱；舊的非同步讀取不會在登出後重新填回表格。管理者列表以 textContent 呈現，UID 作為核准鍵，email 只供辨識。已註冊／已驗證／已核准各自統計，已核准總數是核准表成員，不代表正在登入的人數。

手動驗證密碼重設、登出、註冊、pending 重新檢查、管理者自我撤銷核准、非管理者直接 RPC、舊帳號資料不變、兩個已核准瀏覽器的即時同步、刪列上移與 Google Sheet 一分鐘更新。名單包含個人 email，僅允許管理者讀取。

## 測試與回復

`node --test tests/access.test.cjs` 執行模擬 DOM/client 的前端權限與競態測試。
`npm install --prefix /tmp/approval-test @electric-sql/pglite` 後，
`PGLITE_PATH=/tmp/approval-test/node_modules/@electric-sql/pglite node --test tests/database.test.cjs`
以臨時 PostgreSQL fixture 驗證 SQL、RLS、RPC、核准及撤銷；不連接 production。

部署前保存 audit 中的函式定義、policies、grants 及完整資料備份。migration 失敗時 transaction 自動回滾；成功後如需回復，先停止前端與 Edge 的存取，由 DB 管理者用備份還原 RPC/schema/permissions。不要只移除 restrictive policy 而重新開放所有已驗證帳號。

設計參考：
- https://supabase.com/docs/guides/database/postgres/row-level-security
- https://supabase.com/docs/guides/realtime/postgres-changes
- https://supabase.com/docs/guides/functions/auth-headers

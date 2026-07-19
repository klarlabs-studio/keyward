// This file was generated with `cornucopia`. Do not modify.

#[derive(Debug)]
pub struct InsertAccountParams<T1: crate::StringSql, T2: crate::StringSql> {
    pub account_id: T1,
    pub email: Option<T2>,
    pub created_epoch: i64,
}
#[derive(Debug)]
pub struct InsertDeviceParams<
    T1: crate::StringSql,
    T2: crate::StringSql,
    T3: crate::StringSql,
    T4: crate::StringSql,
> {
    pub device_id: T1,
    pub account_id: T2,
    pub label: T3,
    pub token_hash: T4,
    pub created_epoch: i64,
    pub expires_epoch: Option<i64>,
}
#[derive(Debug)]
pub struct AccountForTokenParams<T1: crate::StringSql> {
    pub token_hash: T1,
    pub now_epoch: i64,
}
#[derive(Debug)]
pub struct ResolveTokenParams<T1: crate::StringSql> {
    pub token_hash: T1,
    pub now_epoch: i64,
}
#[derive(Debug)]
pub struct ResolveTokenForUpdateParams<T1: crate::StringSql> {
    pub token_hash: T1,
    pub now_epoch: i64,
}
#[derive(Debug)]
pub struct UpdateDeviceTokenParams<T1: crate::StringSql, T2: crate::StringSql> {
    pub token_hash: T1,
    pub device_id: T2,
}
#[derive(Debug)]
pub struct RevokeDeviceParams<T1: crate::StringSql, T2: crate::StringSql> {
    pub account_id: T1,
    pub device_id: T2,
}
#[derive(Debug)]
pub struct SetPlanParams<T1: crate::StringSql, T2: crate::StringSql> {
    pub plan: T1,
    pub account_id: T2,
}
#[derive(Debug, Clone, PartialEq)]
pub struct ResolveToken {
    pub device_id: String,
    pub account_id: String,
}
pub struct ResolveTokenBorrowed<'a> {
    pub device_id: &'a str,
    pub account_id: &'a str,
}
impl<'a> From<ResolveTokenBorrowed<'a>> for ResolveToken {
    fn from(
        ResolveTokenBorrowed {
            device_id,
            account_id,
        }: ResolveTokenBorrowed<'a>,
    ) -> Self {
        Self {
            device_id: device_id.into(),
            account_id: account_id.into(),
        }
    }
}
#[derive(Debug, Clone, PartialEq)]
pub struct ResolveTokenForUpdate {
    pub device_id: String,
    pub account_id: String,
}
pub struct ResolveTokenForUpdateBorrowed<'a> {
    pub device_id: &'a str,
    pub account_id: &'a str,
}
impl<'a> From<ResolveTokenForUpdateBorrowed<'a>> for ResolveTokenForUpdate {
    fn from(
        ResolveTokenForUpdateBorrowed {
            device_id,
            account_id,
        }: ResolveTokenForUpdateBorrowed<'a>,
    ) -> Self {
        Self {
            device_id: device_id.into(),
            account_id: account_id.into(),
        }
    }
}
#[derive(Debug, Clone, PartialEq)]
pub struct ListDevices {
    pub device_id: String,
    pub label: String,
    pub created_epoch: i64,
    pub expires_epoch: Option<i64>,
}
pub struct ListDevicesBorrowed<'a> {
    pub device_id: &'a str,
    pub label: &'a str,
    pub created_epoch: i64,
    pub expires_epoch: Option<i64>,
}
impl<'a> From<ListDevicesBorrowed<'a>> for ListDevices {
    fn from(
        ListDevicesBorrowed {
            device_id,
            label,
            created_epoch,
            expires_epoch,
        }: ListDevicesBorrowed<'a>,
    ) -> Self {
        Self {
            device_id: device_id.into(),
            label: label.into(),
            created_epoch,
            expires_epoch,
        }
    }
}
use crate::client::sync::GenericClient;
use postgres::fallible_iterator::FallibleIterator;
pub struct StringQuery<'c, 'a, 's, C: GenericClient, T, const N: usize> {
    client: &'c mut C,
    params: [&'a (dyn postgres_types::ToSql + Sync); N],
    query: &'static str,
    cached: Option<&'s postgres::Statement>,
    extractor: fn(&postgres::Row) -> Result<&str, postgres::Error>,
    mapper: fn(&str) -> T,
}
impl<'c, 'a, 's, C, T: 'c, const N: usize> StringQuery<'c, 'a, 's, C, T, N>
where
    C: GenericClient,
{
    pub fn map<R>(self, mapper: fn(&str) -> R) -> StringQuery<'c, 'a, 's, C, R, N> {
        StringQuery {
            client: self.client,
            params: self.params,
            query: self.query,
            cached: self.cached,
            extractor: self.extractor,
            mapper,
        }
    }
    pub fn one(self) -> Result<T, postgres::Error> {
        let row = crate::client::sync::one(self.client, self.query, &self.params, self.cached)?;
        Ok((self.mapper)((self.extractor)(&row)?))
    }
    pub fn all(self) -> Result<Vec<T>, postgres::Error> {
        self.iter()?.collect()
    }
    pub fn opt(self) -> Result<Option<T>, postgres::Error> {
        let opt_row = crate::client::sync::opt(self.client, self.query, &self.params, self.cached)?;
        Ok(opt_row
            .map(|row| {
                let extracted = (self.extractor)(&row)?;
                Ok((self.mapper)(extracted))
            })
            .transpose()?)
    }
    pub fn iter(
        self,
    ) -> Result<impl Iterator<Item = Result<T, postgres::Error>> + 'c, postgres::Error> {
        let stream = crate::client::sync::raw(
            self.client,
            self.query,
            crate::slice_iter(&self.params),
            self.cached,
        )?;
        let mapped = stream.iterator().map(move |res| {
            res.and_then(|row| {
                let extracted = (self.extractor)(&row)?;
                Ok((self.mapper)(extracted))
            })
        });
        Ok(mapped)
    }
}
pub struct ResolveTokenQuery<'c, 'a, 's, C: GenericClient, T, const N: usize> {
    client: &'c mut C,
    params: [&'a (dyn postgres_types::ToSql + Sync); N],
    query: &'static str,
    cached: Option<&'s postgres::Statement>,
    extractor: fn(&postgres::Row) -> Result<ResolveTokenBorrowed, postgres::Error>,
    mapper: fn(ResolveTokenBorrowed) -> T,
}
impl<'c, 'a, 's, C, T: 'c, const N: usize> ResolveTokenQuery<'c, 'a, 's, C, T, N>
where
    C: GenericClient,
{
    pub fn map<R>(
        self,
        mapper: fn(ResolveTokenBorrowed) -> R,
    ) -> ResolveTokenQuery<'c, 'a, 's, C, R, N> {
        ResolveTokenQuery {
            client: self.client,
            params: self.params,
            query: self.query,
            cached: self.cached,
            extractor: self.extractor,
            mapper,
        }
    }
    pub fn one(self) -> Result<T, postgres::Error> {
        let row = crate::client::sync::one(self.client, self.query, &self.params, self.cached)?;
        Ok((self.mapper)((self.extractor)(&row)?))
    }
    pub fn all(self) -> Result<Vec<T>, postgres::Error> {
        self.iter()?.collect()
    }
    pub fn opt(self) -> Result<Option<T>, postgres::Error> {
        let opt_row = crate::client::sync::opt(self.client, self.query, &self.params, self.cached)?;
        Ok(opt_row
            .map(|row| {
                let extracted = (self.extractor)(&row)?;
                Ok((self.mapper)(extracted))
            })
            .transpose()?)
    }
    pub fn iter(
        self,
    ) -> Result<impl Iterator<Item = Result<T, postgres::Error>> + 'c, postgres::Error> {
        let stream = crate::client::sync::raw(
            self.client,
            self.query,
            crate::slice_iter(&self.params),
            self.cached,
        )?;
        let mapped = stream.iterator().map(move |res| {
            res.and_then(|row| {
                let extracted = (self.extractor)(&row)?;
                Ok((self.mapper)(extracted))
            })
        });
        Ok(mapped)
    }
}
pub struct ResolveTokenForUpdateQuery<'c, 'a, 's, C: GenericClient, T, const N: usize> {
    client: &'c mut C,
    params: [&'a (dyn postgres_types::ToSql + Sync); N],
    query: &'static str,
    cached: Option<&'s postgres::Statement>,
    extractor: fn(&postgres::Row) -> Result<ResolveTokenForUpdateBorrowed, postgres::Error>,
    mapper: fn(ResolveTokenForUpdateBorrowed) -> T,
}
impl<'c, 'a, 's, C, T: 'c, const N: usize> ResolveTokenForUpdateQuery<'c, 'a, 's, C, T, N>
where
    C: GenericClient,
{
    pub fn map<R>(
        self,
        mapper: fn(ResolveTokenForUpdateBorrowed) -> R,
    ) -> ResolveTokenForUpdateQuery<'c, 'a, 's, C, R, N> {
        ResolveTokenForUpdateQuery {
            client: self.client,
            params: self.params,
            query: self.query,
            cached: self.cached,
            extractor: self.extractor,
            mapper,
        }
    }
    pub fn one(self) -> Result<T, postgres::Error> {
        let row = crate::client::sync::one(self.client, self.query, &self.params, self.cached)?;
        Ok((self.mapper)((self.extractor)(&row)?))
    }
    pub fn all(self) -> Result<Vec<T>, postgres::Error> {
        self.iter()?.collect()
    }
    pub fn opt(self) -> Result<Option<T>, postgres::Error> {
        let opt_row = crate::client::sync::opt(self.client, self.query, &self.params, self.cached)?;
        Ok(opt_row
            .map(|row| {
                let extracted = (self.extractor)(&row)?;
                Ok((self.mapper)(extracted))
            })
            .transpose()?)
    }
    pub fn iter(
        self,
    ) -> Result<impl Iterator<Item = Result<T, postgres::Error>> + 'c, postgres::Error> {
        let stream = crate::client::sync::raw(
            self.client,
            self.query,
            crate::slice_iter(&self.params),
            self.cached,
        )?;
        let mapped = stream.iterator().map(move |res| {
            res.and_then(|row| {
                let extracted = (self.extractor)(&row)?;
                Ok((self.mapper)(extracted))
            })
        });
        Ok(mapped)
    }
}
pub struct ListDevicesQuery<'c, 'a, 's, C: GenericClient, T, const N: usize> {
    client: &'c mut C,
    params: [&'a (dyn postgres_types::ToSql + Sync); N],
    query: &'static str,
    cached: Option<&'s postgres::Statement>,
    extractor: fn(&postgres::Row) -> Result<ListDevicesBorrowed, postgres::Error>,
    mapper: fn(ListDevicesBorrowed) -> T,
}
impl<'c, 'a, 's, C, T: 'c, const N: usize> ListDevicesQuery<'c, 'a, 's, C, T, N>
where
    C: GenericClient,
{
    pub fn map<R>(
        self,
        mapper: fn(ListDevicesBorrowed) -> R,
    ) -> ListDevicesQuery<'c, 'a, 's, C, R, N> {
        ListDevicesQuery {
            client: self.client,
            params: self.params,
            query: self.query,
            cached: self.cached,
            extractor: self.extractor,
            mapper,
        }
    }
    pub fn one(self) -> Result<T, postgres::Error> {
        let row = crate::client::sync::one(self.client, self.query, &self.params, self.cached)?;
        Ok((self.mapper)((self.extractor)(&row)?))
    }
    pub fn all(self) -> Result<Vec<T>, postgres::Error> {
        self.iter()?.collect()
    }
    pub fn opt(self) -> Result<Option<T>, postgres::Error> {
        let opt_row = crate::client::sync::opt(self.client, self.query, &self.params, self.cached)?;
        Ok(opt_row
            .map(|row| {
                let extracted = (self.extractor)(&row)?;
                Ok((self.mapper)(extracted))
            })
            .transpose()?)
    }
    pub fn iter(
        self,
    ) -> Result<impl Iterator<Item = Result<T, postgres::Error>> + 'c, postgres::Error> {
        let stream = crate::client::sync::raw(
            self.client,
            self.query,
            crate::slice_iter(&self.params),
            self.cached,
        )?;
        let mapped = stream.iterator().map(move |res| {
            res.and_then(|row| {
                let extracted = (self.extractor)(&row)?;
                Ok((self.mapper)(extracted))
            })
        });
        Ok(mapped)
    }
}
pub struct InsertAccountStmt(&'static str, Option<postgres::Statement>);
pub fn insert_account() -> InsertAccountStmt {
    InsertAccountStmt(
        "INSERT INTO accounts (account_id, email, plan, created_epoch) VALUES ($1, $2, 'free', $3)",
        None,
    )
}
impl InsertAccountStmt {
    pub fn prepare<'a, C: GenericClient>(
        mut self,
        client: &'a mut C,
    ) -> Result<Self, postgres::Error> {
        self.1 = Some(client.prepare(self.0)?);
        Ok(self)
    }
    pub fn bind<'c, 'a, 's, C: GenericClient, T1: crate::StringSql, T2: crate::StringSql>(
        &'s self,
        client: &'c mut C,
        account_id: &'a T1,
        email: &'a Option<T2>,
        created_epoch: &'a i64,
    ) -> Result<u64, postgres::Error> {
        client.execute(self.0, &[account_id, email, created_epoch])
    }
}
impl<'c, 'a, 's, C: GenericClient, T1: crate::StringSql, T2: crate::StringSql>
    crate::client::sync::Params<
        'c,
        'a,
        's,
        InsertAccountParams<T1, T2>,
        Result<u64, postgres::Error>,
        C,
    > for InsertAccountStmt
{
    fn params(
        &'s self,
        client: &'c mut C,
        params: &'a InsertAccountParams<T1, T2>,
    ) -> Result<u64, postgres::Error> {
        self.bind(
            client,
            &params.account_id,
            &params.email,
            &params.created_epoch,
        )
    }
}
pub struct InsertDeviceStmt(&'static str, Option<postgres::Statement>);
pub fn insert_device() -> InsertDeviceStmt {
    InsertDeviceStmt(
        "INSERT INTO devices (device_id, account_id, label, token_hash, created_epoch, expires_epoch) VALUES ($1, $2, $3, $4, $5, $6)",
        None,
    )
}
impl InsertDeviceStmt {
    pub fn prepare<'a, C: GenericClient>(
        mut self,
        client: &'a mut C,
    ) -> Result<Self, postgres::Error> {
        self.1 = Some(client.prepare(self.0)?);
        Ok(self)
    }
    pub fn bind<
        'c,
        'a,
        's,
        C: GenericClient,
        T1: crate::StringSql,
        T2: crate::StringSql,
        T3: crate::StringSql,
        T4: crate::StringSql,
    >(
        &'s self,
        client: &'c mut C,
        device_id: &'a T1,
        account_id: &'a T2,
        label: &'a T3,
        token_hash: &'a T4,
        created_epoch: &'a i64,
        expires_epoch: &'a Option<i64>,
    ) -> Result<u64, postgres::Error> {
        client.execute(
            self.0,
            &[
                device_id,
                account_id,
                label,
                token_hash,
                created_epoch,
                expires_epoch,
            ],
        )
    }
}
impl<
    'c,
    'a,
    's,
    C: GenericClient,
    T1: crate::StringSql,
    T2: crate::StringSql,
    T3: crate::StringSql,
    T4: crate::StringSql,
>
    crate::client::sync::Params<
        'c,
        'a,
        's,
        InsertDeviceParams<T1, T2, T3, T4>,
        Result<u64, postgres::Error>,
        C,
    > for InsertDeviceStmt
{
    fn params(
        &'s self,
        client: &'c mut C,
        params: &'a InsertDeviceParams<T1, T2, T3, T4>,
    ) -> Result<u64, postgres::Error> {
        self.bind(
            client,
            &params.device_id,
            &params.account_id,
            &params.label,
            &params.token_hash,
            &params.created_epoch,
            &params.expires_epoch,
        )
    }
}
pub struct AccountForTokenStmt(&'static str, Option<postgres::Statement>);
pub fn account_for_token() -> AccountForTokenStmt {
    AccountForTokenStmt(
        "SELECT account_id FROM devices WHERE token_hash = $1 AND (expires_epoch IS NULL OR expires_epoch > $2)",
        None,
    )
}
impl AccountForTokenStmt {
    pub fn prepare<'a, C: GenericClient>(
        mut self,
        client: &'a mut C,
    ) -> Result<Self, postgres::Error> {
        self.1 = Some(client.prepare(self.0)?);
        Ok(self)
    }
    pub fn bind<'c, 'a, 's, C: GenericClient, T1: crate::StringSql>(
        &'s self,
        client: &'c mut C,
        token_hash: &'a T1,
        now_epoch: &'a i64,
    ) -> StringQuery<'c, 'a, 's, C, String, 2> {
        StringQuery {
            client,
            params: [token_hash, now_epoch],
            query: self.0,
            cached: self.1.as_ref(),
            extractor: |row| Ok(row.try_get(0)?),
            mapper: |it| it.into(),
        }
    }
}
impl<'c, 'a, 's, C: GenericClient, T1: crate::StringSql>
    crate::client::sync::Params<
        'c,
        'a,
        's,
        AccountForTokenParams<T1>,
        StringQuery<'c, 'a, 's, C, String, 2>,
        C,
    > for AccountForTokenStmt
{
    fn params(
        &'s self,
        client: &'c mut C,
        params: &'a AccountForTokenParams<T1>,
    ) -> StringQuery<'c, 'a, 's, C, String, 2> {
        self.bind(client, &params.token_hash, &params.now_epoch)
    }
}
pub struct ResolveTokenStmt(&'static str, Option<postgres::Statement>);
pub fn resolve_token() -> ResolveTokenStmt {
    ResolveTokenStmt(
        "SELECT device_id, account_id FROM devices WHERE token_hash = $1 AND (expires_epoch IS NULL OR expires_epoch > $2)",
        None,
    )
}
impl ResolveTokenStmt {
    pub fn prepare<'a, C: GenericClient>(
        mut self,
        client: &'a mut C,
    ) -> Result<Self, postgres::Error> {
        self.1 = Some(client.prepare(self.0)?);
        Ok(self)
    }
    pub fn bind<'c, 'a, 's, C: GenericClient, T1: crate::StringSql>(
        &'s self,
        client: &'c mut C,
        token_hash: &'a T1,
        now_epoch: &'a i64,
    ) -> ResolveTokenQuery<'c, 'a, 's, C, ResolveToken, 2> {
        ResolveTokenQuery {
            client,
            params: [token_hash, now_epoch],
            query: self.0,
            cached: self.1.as_ref(),
            extractor: |row: &postgres::Row| -> Result<ResolveTokenBorrowed, postgres::Error> {
                Ok(ResolveTokenBorrowed {
                    device_id: row.try_get(0)?,
                    account_id: row.try_get(1)?,
                })
            },
            mapper: |it| ResolveToken::from(it),
        }
    }
}
impl<'c, 'a, 's, C: GenericClient, T1: crate::StringSql>
    crate::client::sync::Params<
        'c,
        'a,
        's,
        ResolveTokenParams<T1>,
        ResolveTokenQuery<'c, 'a, 's, C, ResolveToken, 2>,
        C,
    > for ResolveTokenStmt
{
    fn params(
        &'s self,
        client: &'c mut C,
        params: &'a ResolveTokenParams<T1>,
    ) -> ResolveTokenQuery<'c, 'a, 's, C, ResolveToken, 2> {
        self.bind(client, &params.token_hash, &params.now_epoch)
    }
}
pub struct ResolveTokenForUpdateStmt(&'static str, Option<postgres::Statement>);
pub fn resolve_token_for_update() -> ResolveTokenForUpdateStmt {
    ResolveTokenForUpdateStmt(
        "SELECT device_id, account_id FROM devices WHERE token_hash = $1 AND (expires_epoch IS NULL OR expires_epoch > $2) FOR UPDATE",
        None,
    )
}
impl ResolveTokenForUpdateStmt {
    pub fn prepare<'a, C: GenericClient>(
        mut self,
        client: &'a mut C,
    ) -> Result<Self, postgres::Error> {
        self.1 = Some(client.prepare(self.0)?);
        Ok(self)
    }
    pub fn bind<'c, 'a, 's, C: GenericClient, T1: crate::StringSql>(
        &'s self,
        client: &'c mut C,
        token_hash: &'a T1,
        now_epoch: &'a i64,
    ) -> ResolveTokenForUpdateQuery<'c, 'a, 's, C, ResolveTokenForUpdate, 2> {
        ResolveTokenForUpdateQuery {
            client,
            params: [token_hash, now_epoch],
            query: self.0,
            cached: self.1.as_ref(),
            extractor:
                |row: &postgres::Row| -> Result<ResolveTokenForUpdateBorrowed, postgres::Error> {
                    Ok(ResolveTokenForUpdateBorrowed {
                        device_id: row.try_get(0)?,
                        account_id: row.try_get(1)?,
                    })
                },
            mapper: |it| ResolveTokenForUpdate::from(it),
        }
    }
}
impl<'c, 'a, 's, C: GenericClient, T1: crate::StringSql>
    crate::client::sync::Params<
        'c,
        'a,
        's,
        ResolveTokenForUpdateParams<T1>,
        ResolveTokenForUpdateQuery<'c, 'a, 's, C, ResolveTokenForUpdate, 2>,
        C,
    > for ResolveTokenForUpdateStmt
{
    fn params(
        &'s self,
        client: &'c mut C,
        params: &'a ResolveTokenForUpdateParams<T1>,
    ) -> ResolveTokenForUpdateQuery<'c, 'a, 's, C, ResolveTokenForUpdate, 2> {
        self.bind(client, &params.token_hash, &params.now_epoch)
    }
}
pub struct UpdateDeviceTokenStmt(&'static str, Option<postgres::Statement>);
pub fn update_device_token() -> UpdateDeviceTokenStmt {
    UpdateDeviceTokenStmt(
        "UPDATE devices SET token_hash = $1 WHERE device_id = $2",
        None,
    )
}
impl UpdateDeviceTokenStmt {
    pub fn prepare<'a, C: GenericClient>(
        mut self,
        client: &'a mut C,
    ) -> Result<Self, postgres::Error> {
        self.1 = Some(client.prepare(self.0)?);
        Ok(self)
    }
    pub fn bind<'c, 'a, 's, C: GenericClient, T1: crate::StringSql, T2: crate::StringSql>(
        &'s self,
        client: &'c mut C,
        token_hash: &'a T1,
        device_id: &'a T2,
    ) -> Result<u64, postgres::Error> {
        client.execute(self.0, &[token_hash, device_id])
    }
}
impl<'c, 'a, 's, C: GenericClient, T1: crate::StringSql, T2: crate::StringSql>
    crate::client::sync::Params<
        'c,
        'a,
        's,
        UpdateDeviceTokenParams<T1, T2>,
        Result<u64, postgres::Error>,
        C,
    > for UpdateDeviceTokenStmt
{
    fn params(
        &'s self,
        client: &'c mut C,
        params: &'a UpdateDeviceTokenParams<T1, T2>,
    ) -> Result<u64, postgres::Error> {
        self.bind(client, &params.token_hash, &params.device_id)
    }
}
pub struct ListDevicesStmt(&'static str, Option<postgres::Statement>);
pub fn list_devices() -> ListDevicesStmt {
    ListDevicesStmt(
        "SELECT device_id, label, created_epoch, expires_epoch FROM devices WHERE account_id = $1 ORDER BY created_epoch",
        None,
    )
}
impl ListDevicesStmt {
    pub fn prepare<'a, C: GenericClient>(
        mut self,
        client: &'a mut C,
    ) -> Result<Self, postgres::Error> {
        self.1 = Some(client.prepare(self.0)?);
        Ok(self)
    }
    pub fn bind<'c, 'a, 's, C: GenericClient, T1: crate::StringSql>(
        &'s self,
        client: &'c mut C,
        account_id: &'a T1,
    ) -> ListDevicesQuery<'c, 'a, 's, C, ListDevices, 1> {
        ListDevicesQuery {
            client,
            params: [account_id],
            query: self.0,
            cached: self.1.as_ref(),
            extractor: |row: &postgres::Row| -> Result<ListDevicesBorrowed, postgres::Error> {
                Ok(ListDevicesBorrowed {
                    device_id: row.try_get(0)?,
                    label: row.try_get(1)?,
                    created_epoch: row.try_get(2)?,
                    expires_epoch: row.try_get(3)?,
                })
            },
            mapper: |it| ListDevices::from(it),
        }
    }
}
pub struct RevokeDeviceStmt(&'static str, Option<postgres::Statement>);
pub fn revoke_device() -> RevokeDeviceStmt {
    RevokeDeviceStmt(
        "DELETE FROM devices WHERE account_id = $1 AND device_id = $2",
        None,
    )
}
impl RevokeDeviceStmt {
    pub fn prepare<'a, C: GenericClient>(
        mut self,
        client: &'a mut C,
    ) -> Result<Self, postgres::Error> {
        self.1 = Some(client.prepare(self.0)?);
        Ok(self)
    }
    pub fn bind<'c, 'a, 's, C: GenericClient, T1: crate::StringSql, T2: crate::StringSql>(
        &'s self,
        client: &'c mut C,
        account_id: &'a T1,
        device_id: &'a T2,
    ) -> Result<u64, postgres::Error> {
        client.execute(self.0, &[account_id, device_id])
    }
}
impl<'c, 'a, 's, C: GenericClient, T1: crate::StringSql, T2: crate::StringSql>
    crate::client::sync::Params<
        'c,
        'a,
        's,
        RevokeDeviceParams<T1, T2>,
        Result<u64, postgres::Error>,
        C,
    > for RevokeDeviceStmt
{
    fn params(
        &'s self,
        client: &'c mut C,
        params: &'a RevokeDeviceParams<T1, T2>,
    ) -> Result<u64, postgres::Error> {
        self.bind(client, &params.account_id, &params.device_id)
    }
}
pub struct GetPlanStmt(&'static str, Option<postgres::Statement>);
pub fn get_plan() -> GetPlanStmt {
    GetPlanStmt("SELECT plan FROM accounts WHERE account_id = $1", None)
}
impl GetPlanStmt {
    pub fn prepare<'a, C: GenericClient>(
        mut self,
        client: &'a mut C,
    ) -> Result<Self, postgres::Error> {
        self.1 = Some(client.prepare(self.0)?);
        Ok(self)
    }
    pub fn bind<'c, 'a, 's, C: GenericClient, T1: crate::StringSql>(
        &'s self,
        client: &'c mut C,
        account_id: &'a T1,
    ) -> StringQuery<'c, 'a, 's, C, String, 1> {
        StringQuery {
            client,
            params: [account_id],
            query: self.0,
            cached: self.1.as_ref(),
            extractor: |row| Ok(row.try_get(0)?),
            mapper: |it| it.into(),
        }
    }
}
pub struct SetPlanStmt(&'static str, Option<postgres::Statement>);
pub fn set_plan() -> SetPlanStmt {
    SetPlanStmt("UPDATE accounts SET plan = $1 WHERE account_id = $2", None)
}
impl SetPlanStmt {
    pub fn prepare<'a, C: GenericClient>(
        mut self,
        client: &'a mut C,
    ) -> Result<Self, postgres::Error> {
        self.1 = Some(client.prepare(self.0)?);
        Ok(self)
    }
    pub fn bind<'c, 'a, 's, C: GenericClient, T1: crate::StringSql, T2: crate::StringSql>(
        &'s self,
        client: &'c mut C,
        plan: &'a T1,
        account_id: &'a T2,
    ) -> Result<u64, postgres::Error> {
        client.execute(self.0, &[plan, account_id])
    }
}
impl<'c, 'a, 's, C: GenericClient, T1: crate::StringSql, T2: crate::StringSql>
    crate::client::sync::Params<'c, 'a, 's, SetPlanParams<T1, T2>, Result<u64, postgres::Error>, C>
    for SetPlanStmt
{
    fn params(
        &'s self,
        client: &'c mut C,
        params: &'a SetPlanParams<T1, T2>,
    ) -> Result<u64, postgres::Error> {
        self.bind(client, &params.plan, &params.account_id)
    }
}
pub struct DeleteDevicesForAccountStmt(&'static str, Option<postgres::Statement>);
pub fn delete_devices_for_account() -> DeleteDevicesForAccountStmt {
    DeleteDevicesForAccountStmt("DELETE FROM devices WHERE account_id = $1", None)
}
impl DeleteDevicesForAccountStmt {
    pub fn prepare<'a, C: GenericClient>(
        mut self,
        client: &'a mut C,
    ) -> Result<Self, postgres::Error> {
        self.1 = Some(client.prepare(self.0)?);
        Ok(self)
    }
    pub fn bind<'c, 'a, 's, C: GenericClient, T1: crate::StringSql>(
        &'s self,
        client: &'c mut C,
        account_id: &'a T1,
    ) -> Result<u64, postgres::Error> {
        client.execute(self.0, &[account_id])
    }
}
pub struct DeleteAccountStmt(&'static str, Option<postgres::Statement>);
pub fn delete_account() -> DeleteAccountStmt {
    DeleteAccountStmt("DELETE FROM accounts WHERE account_id = $1", None)
}
impl DeleteAccountStmt {
    pub fn prepare<'a, C: GenericClient>(
        mut self,
        client: &'a mut C,
    ) -> Result<Self, postgres::Error> {
        self.1 = Some(client.prepare(self.0)?);
        Ok(self)
    }
    pub fn bind<'c, 'a, 's, C: GenericClient, T1: crate::StringSql>(
        &'s self,
        client: &'c mut C,
        account_id: &'a T1,
    ) -> Result<u64, postgres::Error> {
        client.execute(self.0, &[account_id])
    }
}

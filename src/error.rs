#![allow(dead_code)]

use std::fmt::{Display, Formatter};

use std::error::Error as StdError;
use std::fmt;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use tokio::task;

use crate::slack;

#[derive(Debug, Clone, Copy)]
pub enum ErrCode {
    Internal,
    AuthFail,
    Forbidden,
    SetupFail,
    DKGFail,
    DKMFail,
    DKRFail,
    DSGFail,
}

impl ErrCode {
    pub fn pack(self) -> AppError {
        return self.pack_with_str("");
    }

    pub fn pack_with_str(self, msg: &str) -> AppError {
        return AppError::new(self, msg.to_string(), None, self.into());
    }

    pub fn pack_with_cause(self, msg: &str, cause: Box<dyn StdError>) -> AppError {
        return AppError::new(self, msg.to_string(), Some(cause), self.into());
    }
}

impl Into<StatusCode> for ErrCode {
    fn into(self) -> StatusCode {
        match self {
            ErrCode::AuthFail => StatusCode::UNAUTHORIZED,
            ErrCode::Forbidden => StatusCode::FORBIDDEN,
            ErrCode::DKGFail => StatusCode::INTERNAL_SERVER_ERROR,
            ErrCode::DKRFail => StatusCode::INTERNAL_SERVER_ERROR,
            ErrCode::DKMFail => StatusCode::INTERNAL_SERVER_ERROR,
            ErrCode::DSGFail => StatusCode::INTERNAL_SERVER_ERROR,
            ErrCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

impl Display for ErrCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MPC.{:?}", self)
    }
}

#[derive(Debug)]
pub struct AppError {
    code: ErrCode,
    message: String,
    cause: Option<Box<dyn StdError>>,
    status_code: StatusCode,
}

impl AppError {
    pub fn new(
        code: ErrCode,
        message: String,
        cause: Option<Box<dyn StdError>>,
        status_code: StatusCode,
    ) -> Self {
        Self {
            code,
            message,
            cause,
            status_code,
        }
    }

    pub fn get_msg(&self) -> String {
        if !self.message.is_empty() {
            return self.message.clone();
        }
        match self.cause {
            Some(ref cause) => {
                return cause.to_string();
            }
            None => {
                return self.code.to_string();
            }
        }
    }

    pub fn get_cause(&self) -> String {
        match self.cause {
            Some(ref cause) => {
                format!("{:?}", cause)
            }
            None => "".to_string(),
        }
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    code: String,
    message: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let err_text = format!("{:} ", self);
        tracing::error!("{}", err_text);
        task::spawn(async {
            let ret = slack::INSTANCE.send(err_text).await;
            if let Err(_err) = ret {
                tracing::error!("{:?}", _err);
            }
        });
        (
            self.status_code,
            Json(ErrorResponse {
                code: self.code.to_string().to_lowercase(),
                message: self.get_msg(),
            }),
        )
            .into_response()
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "app-error [code:{:} msg:'{:}']\t{:}",
            self.code.to_string(),
            self.get_msg(),
            self.get_cause()
        )
    }
}

impl StdError for AppError {}

// impl From<EncodeError> for AppError {
//     fn from(v: EncodeError) -> Self {
//         ErrCode::Internal.pack_with_str(v.to_string().as_str())
//     }
// }

impl From<anyhow::Error> for AppError {
    fn from(v: anyhow::Error) -> Self {
        ErrCode::Internal.pack_with_cause("", v.into())
    }
}

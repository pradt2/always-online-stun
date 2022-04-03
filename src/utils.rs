use std::fmt::Display;
use std::future::Future;
use std::rc::Rc;
use tokio::sync::Semaphore;

pub(crate) async fn join_all_with_semaphore<T: Iterator<Item=U>, U: Future<Output = V>, V> (
    it: T,
    permits: usize,
) -> Vec<V> {
    let semaphore = Rc::new(Semaphore::new(permits));
    let pending_futures = it.map(|it| {
        let semaphore_local = semaphore.clone();
        async move {
            let permit = semaphore_local.acquire().await.unwrap();
            let output = it.await;
            drop(permit);
            output
        }
    }).collect::<Vec<_>>();
    let resolved_futures = futures::future::join_all(pending_futures).await;
    resolved_futures
}

pub(crate) trait ReduceToString<U: Display> : Iterator<Item=U> {
    fn reduce_to_string(self) -> String where Self: Sized {
        let mut s = String::from("");
        for it in self {
            s.push_str(it.to_string().as_str());
        }
        s
    }
}

impl <I: Iterator<Item=U>, U: Display> ReduceToString<U> for I {}
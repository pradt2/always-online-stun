type Measurement<T> = Option<T>;

trait Subject<T> {
    fn get_measurement(&self) -> Measurement<T>;
}

#[derive(Debug, PartialEq)]
enum TestOutcome {
    Pass,
    Fail,
    Void,
    Error,
}

fn test_measurement<U: PartialEq>(major: &Measurement<U>, minor_a: &Measurement<U>, minor_b: &Measurement<U>) -> TestOutcome {
    if major.is_none() {
        TestOutcome::Fail
    } else if minor_a.is_none() && minor_b.is_none() {
        TestOutcome::Void
    } else if major == minor_a || major == minor_b {
        TestOutcome::Pass
    } else if minor_a == minor_b {
        TestOutcome::Fail
    } else if minor_a.is_some() && minor_b.is_some() {
        TestOutcome::Error
    } else {
        TestOutcome::Void
    }
}

fn test<T: Subject<U>, U: PartialEq>(a: &T, b: &T, c: &T) -> (TestOutcome, TestOutcome, TestOutcome) {
    let a = a.get_measurement();
    let b = b.get_measurement();
    let c = c.get_measurement();

    let outcome_a = test_measurement(&a, &b, &c);
    let outcome_b = test_measurement(&b, &a, &c);
    let outcome_c = test_measurement(&c, &a, &b);

    (outcome_a, outcome_b, outcome_c)
}

enum TestError {
    ABCFailure
}

type TestResult<T> = Result<(Vec<T>, Vec<T>), TestError>;

fn test_colls<T: Subject<U>, U: PartialEq>(mut subs: Vec<T>) -> TestResult<T> {
    let mut passed = vec![];
    let mut failed = vec![];

    while let Some(a) = subs.pop() {
        let mut is_b_from_passed = false;
        let b = if let Some(b) = subs.pop() {
            Some(b)
        } else if let Some(b) = passed.pop() {
            is_b_from_passed = true;
            Some(b)
        } else {
            warn!("Not enough tested/passed subjects to continue testing");
            None
        };

        let b = if let Some(b) = b { b } else { break; };

        let mut is_c_from_passed = false;
        let c = if let Some(c) = subs.pop() {
            Some(c)
        } else if let Some(c) = passed.pop() {
            is_c_from_passed = true;
            Some(c)
        } else {
            warn!("Not enough tested/passed subjects to continue testing");
            None
        };

        let c = if let Some(c) = c { c } else { break; };

        let (outcome_a, outcome_b, outcome_c) = test(&a, &b, &c);

        match outcome_a {
            TestOutcome::Pass => passed.push(a),
            TestOutcome::Fail => failed.push(a),
            TestOutcome::Void => subs.push(a),
            TestOutcome::Error => return Err(TestError::ABCFailure)
        }

        match outcome_b {
            TestOutcome::Pass => passed.push(b),
            TestOutcome::Fail => failed.push(b),
            TestOutcome::Void => if is_b_from_passed {
                passed.push(b);
            } else {
                subs.push(b);
            },
            TestOutcome::Error => return Err(TestError::ABCFailure)
        }

        match outcome_c {
            TestOutcome::Pass => passed.push(c),
            TestOutcome::Fail => failed.push(c),
            TestOutcome::Void => if is_c_from_passed {
                passed.push(c);
            } else {
                subs.push(c);
            },
            TestOutcome::Error => return Err(TestError::ABCFailure)
        }
    }

    return Ok((passed, failed));
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestSubject<T: Copy> {
        measurement: Measurement<T>,
    }

    impl<T: Copy> TestSubject<T> {
        fn new(val: T) -> Self {
            Self {
                measurement: Some(val)
            }
        }

        fn empty() -> Self {
            Self {
                measurement: None
            }
        }
    }

    impl<T: Copy> Subject<T> for TestSubject<T> {
        fn get_measurement(&self) -> Measurement<T> {
            self.measurement
        }
    }

    #[test]
    fn test_mo1() {
        let (a, b, c) = test::<TestSubject<u8>, u8>(&TestSubject::empty(), &TestSubject::empty(), &TestSubject::empty());
        assert_eq!(a, TestOutcome::Fail);
        assert_eq!(b, TestOutcome::Fail);
        assert_eq!(c, TestOutcome::Fail);
    }

    #[test]
    fn test_mo2() {
        let (a, b, c) = test(&TestSubject::empty(), &TestSubject::empty(), &TestSubject::new(1));
        assert_eq!(a, TestOutcome::Fail);
        assert_eq!(b, TestOutcome::Fail);
        assert_eq!(c, TestOutcome::Void);
    }

    #[test]
    fn test_mo3() {
        let (a, b, c) = test(&TestSubject::empty(), &TestSubject::new(1), &TestSubject::new(1));
        assert_eq!(a, TestOutcome::Fail);
        assert_eq!(b, TestOutcome::Pass);
        assert_eq!(c, TestOutcome::Pass);
    }

    #[test]
    fn test_mo4() {
        let (a, b, c) = test(&TestSubject::new(1), &TestSubject::new(1), &TestSubject::new(1));
        assert_eq!(a, TestOutcome::Pass);
        assert_eq!(b, TestOutcome::Pass);
        assert_eq!(c, TestOutcome::Pass);
    }

    #[test]
    fn test_mo5() {
        let (a, b, c) = test(&TestSubject::empty(), &TestSubject::new(1), &TestSubject::new(2));
        assert_eq!(a, TestOutcome::Fail);
        assert_eq!(b, TestOutcome::Void);
        assert_eq!(c, TestOutcome::Void);
    }

    #[test]
    fn test_mo6() {
        let (a, b, c) = test(&TestSubject::new(1), &TestSubject::new(1), &TestSubject::new(2));
        assert_eq!(a, TestOutcome::Pass);
        assert_eq!(b, TestOutcome::Pass);
        assert_eq!(c, TestOutcome::Fail);
    }

    #[test]
    fn test_mo7() {
        let (a, b, c) = test(&TestSubject::new(1), &TestSubject::new(2), &TestSubject::new(3));
        assert_eq!(a, TestOutcome::Error);
        assert_eq!(b, TestOutcome::Error);
        assert_eq!(c, TestOutcome::Error);
    }

    #[test]
    fn test_coll_empty() {
        let colls: Vec<TestSubject<u8>> = vec![];
        match test_colls(colls) {
            Ok((passed, failed)) => {
                assert_eq!(passed.len(), 0);
                assert_eq!(failed.len(), 0);
            }
            Err(_) => assert!(false, "This should never happen")
        }
    }

    #[test]
    fn test_coll_not_enough_test_subjects() {
        let colls: Vec<TestSubject<u8>> = vec![TestSubject::empty(), TestSubject::empty()];
        match test_colls(colls) {
            Ok((passed, failed)) => {
                assert_eq!(passed.len(), 0);
                assert_eq!(failed.len(), 0);
            }
            Err(_) => assert!(false, "This should never happen")
        }
    }

    #[test]
    fn test_coll_just_enough_test_subjects() {
        let colls: Vec<TestSubject<u8>> = vec![TestSubject::empty(), TestSubject::new(1), TestSubject::new(1)];
        match test_colls(colls) {
            Ok((passed, failed)) => {
                assert_eq!(passed.len(), 2);
                assert_eq!(failed.len(), 1);
            }
            Err(_) => assert!(false, "This should never happen")
        }
    }

    #[test]
    fn test_coll_test_err() {
        let colls: Vec<TestSubject<u8>> = vec![TestSubject::new(1), TestSubject::new(2), TestSubject::new(3)];
        match test_colls(colls) {
            Ok((passed, failed)) => assert!(false, "This should never happen"),
            Err(_) => assert!(true)
        }
    }

    #[test]
    fn test_coll_test_subjects() {
        let colls: Vec<TestSubject<u8>> = vec![
            TestSubject::new(1),
            TestSubject::empty(),
            TestSubject::new(1),
            TestSubject::empty(),
            TestSubject::new(1),
            TestSubject::empty(),
            TestSubject::new(1),
            TestSubject::empty(),
            TestSubject::new(1),
            TestSubject::empty(),
            TestSubject::new(1),
            TestSubject::empty(),
        ];
        match test_colls(colls) {
            Ok((passed, failed)) => {
                assert_eq!(passed.len(), 6);
                assert_eq!(failed.len(), 6);
            }
            Err(_) => assert!(false, "This should never happen")
        }
    }

    struct ChangingTestSubject<T> {
        last_idx: usize,
        vals: Vec<Measurement<T>>,
    }

    impl<T: Copy> ChangingTestSubject<T> {
        fn new(vals: Vec<Measurement<T>>) -> Self {
            Self {
                last_idx: 0,
                vals,
            }
        }

        fn empty() -> Self {
            Self {
                last_idx: 0,
                vals: vec![],
            }
        }
    }

    impl<T: Copy> Subject<T> for ChangingTestSubject<T> {
        fn get_measurement(&self) -> Measurement<T> {
            unsafe {
                let self_ptr: *const Self = self;
                let self_mut = self_ptr as *mut Self;
                let idx = self.last_idx;
                (*self_mut).last_idx = (self.last_idx + 1) % self.vals.len();
                self.vals[idx]
            }
        }
    }

    #[test]
    fn test_coll_changing_subjects() {
        let colls = vec![
            ChangingTestSubject::new(vec![None, Some(1)]),
            ChangingTestSubject::new(vec![Some(1)]),
            ChangingTestSubject::new(vec![Some(1)]),
        ];
        match test_colls(colls) {
            Ok((passed, failed)) => {
                assert_eq!(passed.len(), 2);
                assert_eq!(failed.len(), 1);
            }
            Err(_) => assert!(false, "This should never happen")
        }
    }

    #[test]
    fn test_coll_changing_subjects_2() {
        let colls = vec![
            ChangingTestSubject::new(vec![Some(1)]),
            ChangingTestSubject::new(vec![Some(2), Some(1)]),
            ChangingTestSubject::new(vec![Some(1)]),
            ChangingTestSubject::new(vec![None]),
        ];
        match test_colls(colls) {
            Ok((passed, failed)) => {
                assert_eq!(passed.len(), 3);
                assert_eq!(failed.len(), 1);
            }
            Err(_) => assert!(false, "This should never happen")
        }
    }

    #[test]
    fn test_coll_changing_subjects_3() {
        let colls = vec![
            ChangingTestSubject::new(vec![Some(1)]),
            ChangingTestSubject::new(vec![Some(2), Some(1)]),
            ChangingTestSubject::new(vec![Some(1), None]),
            ChangingTestSubject::new(vec![None]),
        ];
        match test_colls(colls) {
            Ok((passed, failed)) => {
                assert_eq!(passed.len(), 2);
                assert_eq!(failed.len(), 2);
            }
            Err(_) => assert!(false, "This should never happen")
        }
    }
}
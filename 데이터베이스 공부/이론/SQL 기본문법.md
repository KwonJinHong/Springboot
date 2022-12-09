# 표준 SQL 기본 문법 정리

 데이터를 조작하기 위해 MySQL, Postgre, SQLite 등 SQL을 사용해야 한다. 이렇게 종류가 다르더라도 관계형 데이터베이스의 SQL문은 기본적인 골겨이 비슷하다. CRUD(Create, Read, Update, Delete) 관련 쿼리를 살펴보자.

## 1. SELECT문 (CRUD 중 Read)
### 1-1. 기본구조
```sql=
SELECT * FROM 테이블명; // 에프터리스크(*)는 모든 열을 의미한다.
SELECT 열명1, 열명2 FROM 테이블명; // 테이블의 열명1 열명2에 대한 행을 조회
```
- 예약어의 데이터베이스 객체명은 대소문자를 구별하지 않는다.
- 표 형식의 데이터는 '행(레코드)'와 '열(컬럼/필드)'로 구성된다.

### 1-2. 조건식을 적용하는 경우
```sql=
SELECT * FROM 테이블 WHERE 조건;
AND 조건2
OR 조건3
```

## 2. INSERT 문 (CRUD 중 Create)
```sql=
INSERT INTO 테이블(필드이름1, 필드이름2) VALUES (값1, 값2);
```

## 3. UPDATE 문 (CRUD 중 Update)
```sql=
UPDATE 테이블 SET 필드이름1=값1, 필드이름2=값2
WHERE 조건문
```

## 4. DELETE 문 (CRUD 중 Delete)
```sql=
DELETE FROM 테이블
WHERE 조건문
```

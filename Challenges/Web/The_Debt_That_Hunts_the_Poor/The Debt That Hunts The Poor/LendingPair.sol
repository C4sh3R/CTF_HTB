// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IERC20.sol";


interface IYieldReset {
    function onLiquidationResetYield(address user) external;
}

contract LendingPair {
    uint256 private constant BPS = 10_000;
    uint16  private constant LTV_BPS = 8000;        // 80%
    uint16  private constant LIQ_THR_BPS = 9000;    // 90%
    uint16  private constant BONUS_BPS = 500;       // 5%
    uint256 private constant VIP_MIN_COLL = 20_000 ether;
    bool public isAccure = false;

    address public immutable tokenA;
    address public immutable tokenB;
    address public immutable yieldShare;
    address public immutable setup;
    address[] public tokens; // tokenA and tokenB

    mapping(address => uint256) public collA;  
    mapping(address => uint256) public collB;     
    mapping(address => uint256) public collYield; 

    mapping(address => uint256) public debtA;    
    mapping(address => uint256) public debtB;    

    event Deposit(address indexed user, address indexed token, uint256 amount);
    event Withdraw(address indexed user, address indexed token, uint256 amount);

    event DepositYield(address indexed user, uint256 shares);
    event WithdrawYield(address indexed user, uint256 shares);

    event Borrow(address indexed user, address indexed token, uint256 amount);
    event Repay(address indexed payer, address indexed onBehalfOf, address indexed token, uint256 amount);

    event Accrue(address indexed user, uint16 bumpBps, uint256 newDebtA, uint256 newDebtB);

    event Liquidate(
        address indexed liquidator,
        address indexed borrower,
        address indexed repayToken,
        uint256 repayAmount,
        address seizeToken,
        uint256 seizeAmount
    );

    constructor(address _tokenA, address _tokenB, address _yieldShare) {
        require(_tokenA != address(0) && _tokenB != address(0) && _yieldShare != address(0), "zero");
        require(_tokenA != _tokenB, "same");

        tokenA = _tokenA;
        tokenB = _tokenB;
        yieldShare = _yieldShare;
        setup = msg.sender;

        tokens.push(_tokenA);
        tokens.push(_tokenB);
    }

    modifier onlySupported(address t) {
        bool ok;
        for (uint256 i = 0; i < tokens.length; i++) {
            if (tokens[i] == t) { ok = true; break; }
        }
        require(ok, "unsupported");
        _;
    }

    modifier onlyVipMember() {
        require(collA[msg.sender] + collB[msg.sender] >= VIP_MIN_COLL, "not VIP");
        _;
    }

    function _safeTransfer(address t, address to, uint256 v) internal {
        require(IERC20(t).transfer(to, v), "transfer fail");
    }

    function _safeTransferFrom(address t, address from, address to, uint256 v) internal {
        require(IERC20(t).transferFrom(from, to, v), "transferFrom fail");
    }

    function _requireReserve(address token, uint256 amount) internal view {
        require(IERC20(token).balanceOf(address(this)) >= amount, "insufficient pool liquidity");
    }


    struct AccountData {
        uint256 coll;
        uint256 debt;   
        uint256 collLtv;
        uint256 collLiq;
    }

    function getAccountData(address user) public view returns (AccountData memory a) {
        a.coll    = collA[user] + collB[user] + collYield[user];
        a.debt    = debtA[user] + debtB[user];
        a.collLtv = (a.coll * LTV_BPS) / BPS;
        a.collLiq = (a.coll * LIQ_THR_BPS) / BPS;
    }

    function isVip(address user) external view returns (bool) {
        return collA[user] + collB[user] >= VIP_MIN_COLL;
    }

    function isLiquidatable(address user) external view returns (bool) {
        AccountData memory a = getAccountData(user);
        return a.debt > a.collLiq;
    }

    function deposit(address token, uint256 amount) external onlySupported(token) {
        require(amount > 0, "zero");
        _safeTransferFrom(token, msg.sender, address(this), amount);
        if (token == tokenA) { collA[msg.sender] += amount; }
        else { collB[msg.sender] += amount; }
        emit Deposit(msg.sender, token, amount);
    }

    function withdraw(address token, uint256 amount) external onlySupported(token) {
        require(amount > 0, "zero");

        if (token == tokenA) {
            require(collA[msg.sender] >= amount, "collA");
            collA[msg.sender] -= amount;
        } else {
            require(collB[msg.sender] >= amount, "collB");
            collB[msg.sender] -= amount;
        }

        AccountData memory a = getAccountData(msg.sender);
        require(a.debt <= a.collLiq, "would be unsafe");

        _safeTransfer(token, msg.sender, amount);
        emit Withdraw(msg.sender, token, amount);
    }

    function depositYield(uint256 shares) external {
        require(shares > 0, "zero");
        _safeTransferFrom(yieldShare, msg.sender, address(this), shares);
        collYield[msg.sender] += shares; 
        emit DepositYield(msg.sender, shares);
    }

    function withdrawYield(uint256 shares) external {
        require(shares > 0, "zero");
        uint256 cur = collYield[msg.sender];
        require(cur >= shares, "not enough");
        collYield[msg.sender] = cur - shares;

        AccountData memory a = getAccountData(msg.sender);
        require(a.debt <= a.collLiq, "would be unsafe");

        _safeTransfer(yieldShare, msg.sender, shares);
        emit WithdrawYield(msg.sender, shares);
    }


    function liquidate(
        address borrower,
        address repayToken,
        uint256 repayAmount,
        address seizeToken
    )
        external
        onlyVipMember
        onlySupported(repayToken)
        onlySupported(seizeToken)
    {
        require(borrower != address(0), "bad borrower"); 
        require(repayAmount > 0, "zero");

        AccountData memory a = getAccountData(borrower);
        require(a.debt > a.collLiq, "not liquidatable");

        if (repayToken == tokenA) {
            uint256 d = debtA[borrower];
            if (repayAmount > d) repayAmount = d;
        } else {
            uint256 d = debtB[borrower];
            if (repayAmount > d) repayAmount = d;
        }

        _safeTransferFrom(repayToken, msg.sender, address(this), repayAmount);

        if (repayToken == tokenA) { debtA[borrower] -= repayAmount; }
        else { debtB[borrower] -= repayAmount; }

        uint256 seizeAmount = (repayAmount * (BPS + BONUS_BPS)) / BPS;

        if (seizeToken == tokenA) {
            require(collA[borrower] >= seizeAmount, "collA<seize");
            collA[borrower] -= seizeAmount;
            _safeTransfer(seizeToken, msg.sender, seizeAmount);
        } else {
            require(collB[borrower] >= seizeAmount, "collB<seize");
            collB[borrower] -= seizeAmount;
            _safeTransfer(seizeToken, msg.sender, seizeAmount);
        }
        IYieldReset(setup).onLiquidationResetYield(borrower);
        isAccure = false;
        emit Liquidate(msg.sender, borrower, repayToken, repayAmount, seizeToken, seizeAmount);
    }

    function borrow(address token, uint256 amount) external onlySupported(token) {
        require(amount > 0, "zero");

        AccountData memory a = getAccountData(msg.sender);
        require(a.debt < a.collLtv, "no cap");
        require(a.debt + amount <= a.collLtv, "exceeds 80%");

        _requireReserve(token, amount);

        if (token == tokenA) { debtA[msg.sender] += amount; }
        else { debtB[msg.sender] += amount; }

        _safeTransfer(token, msg.sender, amount);
        emit Borrow(msg.sender, token, amount);
    }

    function repay(address token, uint256 amount, address onBehalfOf) external onlySupported(token) {
        require(amount > 0, "zero");
        if (onBehalfOf == address(0)) onBehalfOf = msg.sender;

        _safeTransferFrom(token, msg.sender, address(this), amount);

        if (token == tokenA) {
            uint256 d = debtA[onBehalfOf];
            uint256 pay = amount > d ? d : amount;
            debtA[onBehalfOf] = d - pay;
            if (amount > pay) _safeTransfer(token, msg.sender, amount - pay); 
        } else {
            uint256 d = debtB[onBehalfOf];
            uint256 pay = amount > d ? d : amount;
            debtB[onBehalfOf] = d - pay;
            if (amount > pay) _safeTransfer(token, msg.sender, amount - pay);
        }

        emit Repay(msg.sender, onBehalfOf, token, amount);
    }


    function accrueFor(address user, uint16 bumpBps) external payable{
        uint256 fee = bumpBps * 2;
        require(user != address(0), "zero user");
        require(msg.value >= fee, "You need to pay extra for this");
        require(bumpBps > 0 && bumpBps <= 2500, "bad bps"); // maxs +25% 
        require(!isAccure, "You already accure before");
        uint256 dA = debtA[user];
        uint256 dB = debtB[user];

        if (dA > 0) {
            uint256 addA = (dA * bumpBps) / BPS;
            unchecked { debtA[user] = dA + addA; }
        }
        if (dB > 0) {
            uint256 addB = (dB * bumpBps) / BPS;
            unchecked { debtB[user] = dB + addB; }
        }
        isAccure = true;
        emit Accrue(user, bumpBps, debtA[user], debtB[user]);
    }
}
